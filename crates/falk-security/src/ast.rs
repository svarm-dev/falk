//! Fail-closed tree-sitter-bash walker.
//!
//! Unknown named node types and `ERROR` nodes are findings. Pipelines, lists,
//! subshells, command/process substitutions are recursed. `bash -c` / `eval`
//! nested arguments are re-parsed. Interpreters themselves are not blocked.

use tree_sitter::{Node, Parser, Tree};

/// A structural or policy-relevant finding produced by the walker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkFinding {
    UnknownNode { kind: String },
    ParseError { snippet: String },
    TooComplex { nodes: usize, depth: usize },
    Nested { inner: Box<WalkFinding> },
}

impl WalkFinding {
    pub fn reason(&self) -> String {
        match self {
            Self::UnknownNode { kind } => format!("unknown AST node `{kind}` (fail-closed)"),
            Self::ParseError { snippet } => {
                format!("bash parse error near `{snippet}` (fail-closed)")
            }
            Self::TooComplex { nodes, depth } => {
                format!("AST too complex (nodes={nodes}, depth={depth})")
            }
            Self::Nested { inner } => format!("nested: {}", inner.reason()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedCommand {
    pub name: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkOutcome {
    pub findings: Vec<WalkFinding>,
    pub commands: Vec<ExtractedCommand>,
    pub node_count: usize,
    pub max_depth: usize,
}

impl WalkOutcome {
    pub fn first_finding(&self) -> Option<&WalkFinding> {
        self.findings.first()
    }
}

/// Named node kinds accepted by the fail-closed walker. Anything else named
/// is blocked. Anonymous punctuation (`&&`, `|`, …) is ignored.
const KNOWN_KINDS: &[&str] = &[
    "program",
    "comment",
    "command",
    "command_name",
    "word",
    "string",
    "string_content",
    "raw_string",
    "ansi_c_string",
    "translated_string",
    "concatenation",
    "number",
    "simple_expansion",
    "expansion",
    "expansion_flags",
    "special_variable_name",
    "variable_name",
    "variable_assignment",
    "subscript",
    "array",
    "pipeline",
    "list",
    "negated_command",
    "subshell",
    "compound_statement",
    "redirected_statement",
    "file_redirect",
    "heredoc_redirect",
    "heredoc_start",
    "heredoc_body",
    "herestring_redirect",
    "file_descriptor",
    "redirect",
    "command_substitution",
    "process_substitution",
    "brace_expansion",
    "brace_expression",
    "arithmetic_expansion",
    "parenthesized_expression",
    "unary_expression",
    "binary_expression",
    "ternary_expression",
    "postfix_expression",
    "test_command",
    "test_operator",
    "declaration_command",
    "unset_command",
    "for_statement",
    "c_style_for_statement",
    "while_statement",
    "until_statement",
    "if_statement",
    "elif_clause",
    "else_clause",
    "case_statement",
    "case_item",
    "function_definition",
    "do_group",
    "if_clause",
    "select_statement",
    "coproc",
    "regex",
    "regex_pattern",
    "extglob_pattern",
    "extquote",
    "heredoc_content",
    "terminator",
    "file_redirect",
];

const SHELL_INTERPRETERS: &[&str] = &["bash", "sh", "dash", "zsh", "ksh", "ash"];
const SCRIPT_INTERPRETERS: &[&str] = &[
    "python", "python3", "node", "nodejs", "ruby", "perl", "lua",
];
const WRAPPERS: &[&str] = &["env", "busybox"];

/// True for shells, script runtimes, and wrappers. Shared with policy so
/// `node` and `nodejs` stay exempt from a nonempty command allowlist.
pub fn is_interpreter_name(base: &str) -> bool {
    let b = base.rsplit('/').next().unwrap_or(base);
    SHELL_INTERPRETERS.contains(&b)
        || SCRIPT_INTERPRETERS.contains(&b)
        || WRAPPERS.contains(&b)
        || b == "eval"
}

const MAX_REPARSE_DEPTH: usize = 8;

/// Parse `source` as bash and walk it fail-closed.
pub fn walk_bash(source: &str, max_depth: usize, max_nodes: usize) -> WalkOutcome {
    walk_bash_inner(source, max_depth, max_nodes, 0)
}

fn walk_bash_inner(
    source: &str,
    max_depth: usize,
    max_nodes: usize,
    reparse_depth: usize,
) -> WalkOutcome {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .is_err()
    {
        return WalkOutcome {
            findings: vec![WalkFinding::ParseError {
                snippet: "failed to load tree-sitter-bash".into(),
            }],
            commands: Vec::new(),
            node_count: 0,
            max_depth: 0,
        };
    }
    let Some(tree) = parser.parse(source, None) else {
        return WalkOutcome {
            findings: vec![WalkFinding::ParseError {
                snippet: source.chars().take(40).collect(),
            }],
            commands: Vec::new(),
            node_count: 0,
            max_depth: 0,
        };
    };
    walk_tree(&tree, source, max_depth, max_nodes, reparse_depth)
}

fn walk_tree(
    tree: &Tree,
    source: &str,
    max_depth: usize,
    max_nodes: usize,
    reparse_depth: usize,
) -> WalkOutcome {
    let root = tree.root_node();
    let mut findings = Vec::new();
    let mut commands = Vec::new();
    let mut node_count = 0usize;
    let mut deepest = 0usize;
    visit(
        root,
        source,
        0,
        max_depth,
        max_nodes,
        reparse_depth,
        &mut findings,
        &mut commands,
        &mut node_count,
        &mut deepest,
    );
    if node_count > max_nodes || deepest > max_depth {
        findings.push(WalkFinding::TooComplex {
            nodes: node_count,
            depth: deepest,
        });
    }
    WalkOutcome {
        findings,
        commands,
        node_count,
        max_depth: deepest,
    }
}

#[allow(clippy::too_many_arguments)]
fn visit(
    node: Node<'_>,
    source: &str,
    depth: usize,
    max_depth: usize,
    max_nodes: usize,
    reparse_depth: usize,
    findings: &mut Vec<WalkFinding>,
    commands: &mut Vec<ExtractedCommand>,
    node_count: &mut usize,
    deepest: &mut usize,
) {
    *node_count += 1;
    if depth > *deepest {
        *deepest = depth;
    }
    if *node_count > max_nodes || depth > max_depth {
        return;
    }

    if node.is_error() || node.is_missing() || node.kind() == "ERROR" {
        let snippet = node
            .utf8_text(source.as_bytes())
            .unwrap_or("")
            .chars()
            .take(48)
            .collect();
        findings.push(WalkFinding::ParseError { snippet });
        return;
    }

    if let Some(finding) = classify_kind(node.kind(), node.is_named()) {
        findings.push(finding);
        // Still recurse so we collect more signal, but the finding stands.
    }

    if node.kind() == "command" {
        if let Some(cmd) = extract_command(node, source) {
            maybe_reparse_nested(
                &cmd,
                max_depth,
                max_nodes,
                reparse_depth,
                findings,
                commands,
            );
            commands.push(cmd);
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        visit(
            child,
            source,
            depth + 1,
            max_depth,
            max_nodes,
            reparse_depth,
            findings,
            commands,
            node_count,
            deepest,
        );
    }
}

fn extract_command(node: Node<'_>, source: &str) -> Option<ExtractedCommand> {
    let mut words = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "command_name" | "word" | "string" | "raw_string" | "concatenation" => {
                if let Ok(text) = child.utf8_text(source.as_bytes()) {
                    words.push(unquote(text));
                }
            }
            _ => {}
        }
    }
    let name = words.first()?.clone();
    let args = words.into_iter().skip(1).collect();
    Some(ExtractedCommand { name, args })
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
        || (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn maybe_reparse_nested(
    cmd: &ExtractedCommand,
    max_depth: usize,
    max_nodes: usize,
    reparse_depth: usize,
    findings: &mut Vec<WalkFinding>,
    commands: &mut Vec<ExtractedCommand>,
) {
    if reparse_depth >= MAX_REPARSE_DEPTH {
        return;
    }
    let base = cmd_basename(&cmd.name);
    if let Some((name, args)) = wrapped_command(base, &cmd.args) {
        let inner = ExtractedCommand { name, args };
        maybe_reparse_nested(
            &inner,
            max_depth,
            max_nodes,
            reparse_depth + 1,
            findings,
            commands,
        );
        commands.push(inner);
        return;
    }
    let nested = nested_script(base, &cmd.args);
    if let Some(script) = nested {
        if SCRIPT_INTERPRETERS.contains(&base) {
            // python/node/perl source is not bash; walk quoted snippets
            // so `os.system('rm …')` still yields `rm`.
            for snippet in quoted_snippets(script) {
                let more = walk_bash_inner(snippet, max_depth, max_nodes, reparse_depth + 1);
                commands.extend(more.commands);
            }
        } else {
            let inner = walk_bash_inner(script, max_depth, max_nodes, reparse_depth + 1);
            for f in inner.findings {
                findings.push(WalkFinding::Nested { inner: Box::new(f) });
            }
            commands.extend(inner.commands);
        }
    }
}

fn quoted_snippets(script: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = script.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let quote = bytes[i];
        if quote == b'\'' || quote == b'"' {
            if let Some(rel) = bytes[i + 1..].iter().position(|&b| b == quote) {
                let start = i + 1;
                let end = start + rel;
                if end > start {
                    out.push(&script[start..end]);
                }
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn cmd_basename(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

/// Interpreters are not blanket-blocked. When we see `bash -c SCRIPT`,
/// `python -c SCRIPT`, `node -e SCRIPT`, or `eval SCRIPT`, re-parse SCRIPT.
fn nested_script<'a>(base: &str, args: &'a [String]) -> Option<&'a str> {
    if SHELL_INTERPRETERS.contains(&base) || SCRIPT_INTERPRETERS.contains(&base) {
        let mut i = 0;
        while i < args.len() {
            let a = args[i].as_str();
            if a == "-c" || a == "--command" || a == "-e" || a == "--eval" {
                return args.get(i + 1).map(String::as_str);
            }
            if SHELL_INTERPRETERS.contains(&base)
                && a.starts_with('-')
                && a.contains('c')
                && a != "-"
                && a != "--"
            {
                // `bash -lc SCRIPT`
                return args.get(i + 1).map(String::as_str);
            }
            i += 1;
        }
    }
    if base == "eval" {
        return args.first().map(String::as_str);
    }
    None
}

/// `env CMD …` / `busybox CMD …`: the real argv0 is the first non-option word.
pub fn wrapped_command(base: &str, args: &[String]) -> Option<(String, Vec<String>)> {
    if !WRAPPERS.contains(&base) {
        return None;
    }
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            i += 1;
            break;
        }
        if a.contains('=') && !a.starts_with('-') {
            i += 1;
            continue;
        }
        if a.starts_with('-') {
            if matches!(a, "-u" | "-C" | "--unset" | "--chdir") {
                i = i.saturating_add(2);
                continue;
            }
            i += 1;
            continue;
        }
        break;
    }
    let name = args.get(i)?.clone();
    let rest = args[i + 1..].to_vec();
    Some((name, rest))
}

/// Classify a tree-sitter node kind. The walker calls this for every node;
/// unknown named kinds are fail-closed findings.
pub fn classify_kind(kind: &str, named: bool) -> Option<WalkFinding> {
    if named && kind != "ERROR" && !KNOWN_KINDS.contains(&kind) {
        Some(WalkFinding::UnknownNode {
            kind: kind.to_string(),
        })
    } else {
        None
    }
}

pub fn is_known_kind(kind: &str) -> bool {
    KNOWN_KINDS.contains(&kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn walk(src: &str) -> WalkOutcome {
        walk_bash(src, 64, 4096)
    }

    #[test]
    fn echo_is_clean() {
        let out = walk("echo hello");
        assert!(out.findings.is_empty(), "{:?}", out.findings);
        assert_eq!(out.commands[0].name, "echo");
    }

    #[test]
    fn unknown_named_node_is_finding() {
        assert!(!is_known_kind("totally_unknown_node_kind"));
        let finding = classify_kind("totally_unknown_node_kind", true)
            .expect("unknown named kind must be a finding");
        assert!(matches!(finding, WalkFinding::UnknownNode { .. }));
        assert!(finding.reason().contains("fail-closed"));
        assert!(classify_kind("command", true).is_none());
        assert!(classify_kind("totally_unknown_node_kind", false).is_none());
    }

    #[test]
    fn pipeline_and_subshell_recurse() {
        let out = walk("(echo a | grep a) && echo b");
        let names: Vec<_> = out.commands.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"echo"), "{names:?}");
        assert!(names.contains(&"grep"), "{names:?}");
    }

    #[test]
    fn bash_c_is_reparsed() {
        let out = walk(r#"bash -c "rm -rf /tmp/falk-demo""#);
        let names: Vec<_> = out.commands.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"rm"),
            "nested rm must be extracted, got {names:?}"
        );
        // bash itself is recorded but is an interpreter, not a finding.
        assert!(names.contains(&"bash"), "{names:?}");
    }

    #[test]
    fn eval_is_reparsed() {
        let out = walk(r#"eval "cat /etc/shadow""#);
        let names: Vec<_> = out.commands.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"cat"), "{names:?}");
    }

    #[test]
    fn env_and_python_c_extract_inner_command() {
        let env = walk("env rm -rf /tmp/x");
        let names: Vec<_> = env.commands.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"rm"),
            "env wrapper must yield rm, got {names:?}"
        );

        let py = walk(r#"python -c "import os; os.system('rm -rf /tmp/x')""#);
        let names: Vec<_> = py.commands.iter().map(|c| c.name.as_str()).collect();
        assert!(
            names.contains(&"rm"),
            "python -c payload must yield rm, got {names:?}"
        );
    }

    #[test]
    fn too_complex_trips() {
        let out = walk_bash("echo a; echo b; echo c", 2, 4);
        assert!(
            out.findings
                .iter()
                .any(|f| matches!(f, WalkFinding::TooComplex { .. })),
            "{:?}",
            out.findings
        );
    }
}
