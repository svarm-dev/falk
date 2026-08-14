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
        let trimmed = line.trim();
        if trimmed.is_empty() {
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
}
