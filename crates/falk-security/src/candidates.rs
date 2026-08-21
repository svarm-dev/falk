//! Hybrid candidate extraction from PTY lines and structured agent JSON.
//!
//! Agents (Claude Code, Aider, Cursor, Codex, …) emit `tool_use` /
//! `function-call` objects alongside raw shell lines. Both are candidates
//! for the policy engine.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub source: CandidateSource,
    pub script: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateSource {
    PtyLine,
    ToolUse,
    FunctionCall,
}

/// Extract shell candidates from a stream chunk. This is the shipped extractor.
pub fn extract_candidates(chunk: &str) -> Vec<Candidate> {
    let mut out = Vec::new();
    for line in chunk.lines() {
        let stripped = strip_ansi(line);
        let trimmed = stripped.trim();
        if trimmed.is_empty() || is_tui_chrome(trimmed) {
            continue;
        }
        if let Some(from_json) = from_structured_json(trimmed) {
            out.extend(from_json);
            continue;
        }
        // Skip obvious non-shell UI chrome.
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
                out.extend(from_json_value(&value));
                continue;
            }
        }
        out.push(Candidate {
            source: CandidateSource::PtyLine,
            script: trimmed.to_string(),
        });
    }
    // Also scan the whole chunk for embedded JSON objects (pretty-printed).
    if chunk.contains("tool_use")
        || chunk.contains("function_call")
        || chunk.contains("functionCall")
    {
        if let Ok(value) = serde_json::from_str::<Value>(chunk) {
            let extra = from_json_value(&value);
            for cand in extra {
                if !out.iter().any(|c| c.script == cand.script) {
                    out.push(cand);
                }
            }
        }
    }
    out
}

fn from_structured_json(line: &str) -> Option<Vec<Candidate>> {
    let value: Value = serde_json::from_str(line).ok()?;
    let found = from_json_value(&value);
    if found.is_empty() { None } else { Some(found) }
}

fn from_json_value(value: &Value) -> Vec<Candidate> {
    let mut out = Vec::new();
    walk_json(value, &mut out);
    out
}

fn walk_json(value: &Value, out: &mut Vec<Candidate>) {
    match value {
        Value::Object(map) => {
            let type_name = map
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            let name = map
                .get("name")
                .and_then(Value::as_str)
                .or_else(|| map.get("function").and_then(Value::as_str))
                .unwrap_or("");

            if type_name.contains("tool")
                || type_name == "tool_use"
                || name == "Bash"
                || name == "bash"
            {
                if let Some(script) = tool_script(map) {
                    out.push(Candidate {
                        source: CandidateSource::ToolUse,
                        script,
                    });
                }
            }
            if type_name.contains("function")
                || map.contains_key("function_call")
                || map.contains_key("functionCall")
            {
                if let Some(script) = function_call_script(value) {
                    out.push(Candidate {
                        source: CandidateSource::FunctionCall,
                        script,
                    });
                }
            }
            for v in map.values() {
                walk_json(v, out);
            }
        }
        Value::Array(items) => {
            for v in items {
                walk_json(v, out);
            }
        }
        _ => {}
    }
}

fn tool_script(map: &serde_json::Map<String, Value>) -> Option<String> {
    let input = map.get("input").or_else(|| map.get("arguments"))?;
    if let Some(s) = input.as_str() {
        return Some(s.to_string());
    }
    let obj = input.as_object()?;
    obj.get("command")
        .or_else(|| obj.get("cmd"))
        .or_else(|| obj.get("script"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Drop CSI/OSC/charset sequences so a TUI redraw is not fed to bash.
pub fn strip_ansi(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b {
            i += 1;
            if i >= bytes.len() {
                break;
            }
            match bytes[i] {
                b'[' => {
                    i += 1;
                    while i < bytes.len() && !(bytes[i].is_ascii_alphabetic() || bytes[i] == b'~') {
                        i += 1;
                    }
                    i = i.saturating_add(1);
                }
                b']' | b'P' | b'X' | b'^' | b'_' => {
                    i += 1;
                    while i < bytes.len() {
                        if bytes[i] == 0x07 {
                            i += 1;
                            break;
                        }
                        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                            i += 2;
                            break;
                        }
                        i += 1;
                    }
                }
                b'(' | b')' | b'*' | b'+' => i = (i + 2).min(bytes.len()),
                _ => i += 1,
            }
            continue;
        }
        let width = utf8_width(bytes[i]);
        let end = (i + width).min(bytes.len());
        out.extend_from_slice(&bytes[i..end]);
        i = end;
    }
    String::from_utf8(out)
        .unwrap_or_else(|err| String::from_utf8_lossy(&err.into_bytes()).into_owned())
}

fn utf8_width(first: u8) -> usize {
    match first {
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => 1,
    }
}

fn is_tui_chrome(line: &str) -> bool {
    let mut visible = 0usize;
    let mut boxy = 0usize;
    for c in line.chars() {
        if c.is_whitespace() {
            continue;
        }
        visible += 1;
        if is_box_drawing(c) {
            boxy += 1;
        }
    }
    visible == 0 || boxy.saturating_mul(2) >= visible
}

fn is_box_drawing(c: char) -> bool {
    matches!(
        c,
        '\u{2500}'..='\u{257F}' | '\u{2580}'..='\u{259F}' | '\u{25A0}'..='\u{25FF}'
    )
}

fn function_call_script(value: &Value) -> Option<String> {
    let call = value
        .get("function_call")
        .or_else(|| value.get("functionCall"))
        .unwrap_or(value);
    let args = call.get("arguments").or_else(|| call.get("args"))?;
    if let Some(s) = args.as_str() {
        if let Ok(parsed) = serde_json::from_str::<Value>(s) {
            return parsed
                .get("command")
                .or_else(|| parsed.get("cmd"))
                .and_then(Value::as_str)
                .map(str::to_string)
                .or(Some(s.to_string()));
        }
        return Some(s.to_string());
    }
    args.get("command")
        .or_else(|| args.get("cmd"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pty_line_is_a_candidate() {
        let c = extract_candidates("ls -la\n");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].source, CandidateSource::PtyLine);
        assert_eq!(c[0].script, "ls -la");
    }

    #[test]
    fn tool_use_json_is_extracted() {
        let chunk = r#"{"type":"tool_use","name":"Bash","input":{"command":"cat /etc/passwd"}}"#;
        let c = extract_candidates(chunk);
        assert!(
            c.iter()
                .any(|x| x.script.contains("cat /etc/passwd")
                    && x.source == CandidateSource::ToolUse),
            "{c:?}"
        );
    }

    #[test]
    fn function_call_json_is_extracted() {
        let chunk = r#"{"function_call":{"name":"run","arguments":"{\"command\":\"echo hi\"}"}}"#;
        let c = extract_candidates(chunk);
        assert!(
            c.iter()
                .any(|x| x.script.contains("echo hi") && x.source == CandidateSource::FunctionCall),
            "{c:?}"
        );
    }

    #[test]
    fn box_drawing_and_ansi_are_not_pty_candidates() {
        let rule = "─".repeat(40);
        assert!(
            extract_candidates(&format!("{rule}\n")).is_empty(),
            "box-drawing rule must not be a shell candidate"
        );
        let ansi = "\x1b[32m\x1b[0m\n";
        assert!(
            extract_candidates(ansi).is_empty(),
            "SGR-only line must not be a shell candidate"
        );
        let c = extract_candidates("\x1b[31mls -la\x1b[0m\n");
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].script, "ls -la");
    }
}
