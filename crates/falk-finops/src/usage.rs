//! Usage-event parsers for representative agent / provider stream shapes.

use rust_decimal::Decimal;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct UsageEvent {
    pub provider: Option<String>,
    pub model_id: Option<String>,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub provider_cost_usd: Option<Decimal>,
    pub estimated: bool,
}

impl Default for UsageEvent {
    fn default() -> Self {
        Self {
            provider: None,
            model_id: None,
            prompt_tokens: 0,
            completion_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            provider_cost_usd: None,
            estimated: false,
        }
    }
}

/// Scan a stream chunk for provider usage events (JSON lines / embedded objects).
pub fn parse_usage_events(chunk: &str) -> Vec<UsageEvent> {
    let mut out = Vec::new();
    for line in chunk.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
            collect_from_value(&value, &mut out);
        }
    }
    if out.is_empty() {
        if let Ok(value) = serde_json::from_str::<Value>(chunk) {
            collect_from_value(&value, &mut out);
        }
    }
    out
}

fn collect_from_value(value: &Value, out: &mut Vec<UsageEvent>) {
    if let Some(event) = event_from_object(value) {
        out.push(event);
    }
    match value {
        Value::Object(map) => {
            for v in map.values() {
                collect_from_value(v, out);
            }
        }
        Value::Array(items) => {
            for v in items {
                collect_from_value(v, out);
            }
        }
        _ => {}
    }
}

fn event_from_object(value: &Value) -> Option<UsageEvent> {
    let obj = value.as_object()?;
    let usage = obj.get("usage").unwrap_or(value);
    let usage_obj = usage.as_object()?;

    let prompt = first_u64(
        usage_obj,
        &[
            "prompt_tokens",
            "input_tokens",
            "inputTokens",
            "promptTokens",
        ],
    );
    let completion = first_u64(
        usage_obj,
        &[
            "completion_tokens",
            "output_tokens",
            "outputTokens",
            "completionTokens",
        ],
    );
    let cache_read = first_u64(
        usage_obj,
        &[
            "cache_read_input_tokens",
            "cache_read_tokens",
            "cached_tokens",
        ],
    );
    let cache_write = first_u64(
        usage_obj,
        &["cache_creation_input_tokens", "cache_write_tokens"],
    );

    let cost = first_decimal(obj, &["provider_cost_usd", "cost_usd", "total_cost_usd"])
        .or_else(|| first_decimal(usage_obj, &["provider_cost_usd", "cost_usd"]));

    let wrapped = obj.contains_key("usage");
    let explicit = obj.get("event").and_then(Value::as_str) == Some("usage");
    let standalone = obj.contains_key("provider")
        || obj.contains_key("model_id")
        || obj.contains_key("model")
        || obj.contains_key("provider_cost_usd")
        || obj.contains_key("cost_usd");
    let has_tokens = prompt.is_some() || completion.is_some() || cache_read.is_some();
    if !(wrapped || explicit || (standalone && (has_tokens || cost.is_some()))) {
        return None;
    }

    let provider = first_str(obj, &["provider"]).or_else(|| first_str(usage_obj, &["provider"]));
    let model_id = first_str(obj, &["model_id", "model", "modelId"])
        .or_else(|| first_str(usage_obj, &["model_id", "model"]));
    let estimated = obj
        .get("estimated")
        .and_then(Value::as_bool)
        .unwrap_or(cost.is_none());

    Some(UsageEvent {
        provider,
        model_id,
        prompt_tokens: prompt.unwrap_or(0),
        completion_tokens: completion.unwrap_or(0),
        cache_read_tokens: cache_read.unwrap_or(0),
        cache_write_tokens: cache_write.unwrap_or(0),
        provider_cost_usd: cost,
        estimated,
    })
}

fn first_u64(obj: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<u64> {
    for k in keys {
        if let Some(v) = obj.get(*k) {
            if let Some(n) = v.as_u64() {
                return Some(n);
            }
            if let Some(n) = v.as_i64() {
                return Some(n.max(0) as u64);
            }
            if let Some(s) = v.as_str() {
                if let Ok(n) = s.parse::<u64>() {
                    return Some(n);
                }
            }
        }
    }
    None
}

fn first_str(obj: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(s) = obj.get(*k).and_then(Value::as_str) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

fn first_decimal(obj: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<Decimal> {
    for k in keys {
        if let Some(v) = obj.get(*k) {
            if let Some(s) = v.as_str() {
                if let Ok(d) = s.parse::<Decimal>() {
                    return Some(d);
                }
            }
            if let Some(f) = v.as_f64() {
                return f.to_string().parse().ok();
            }
            if let Some(n) = v.as_i64() {
                return Some(Decimal::from(n));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_style() {
        let ev = parse_usage_events(
            r#"{"model":"gpt-4o","usage":{"prompt_tokens":11,"completion_tokens":7}}"#,
        );
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].prompt_tokens, 11);
        assert_eq!(ev[0].completion_tokens, 7);
        assert_eq!(ev[0].model_id.as_deref(), Some("gpt-4o"));
    }

    #[test]
    fn anthropic_style_with_cache_and_cost() {
        let ev = parse_usage_events(
            r#"{"provider":"anthropic","model_id":"claude-sonnet-4","usage":{"input_tokens":100,"output_tokens":20,"cache_read_input_tokens":5},"provider_cost_usd":"0.012"}"#,
        );
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].prompt_tokens, 100);
        assert_eq!(ev[0].cache_read_tokens, 5);
        assert_eq!(ev[0].provider.as_deref(), Some("anthropic"));
        assert!(ev[0].provider_cost_usd.is_some());
        assert!(!ev[0].estimated);
    }
}
