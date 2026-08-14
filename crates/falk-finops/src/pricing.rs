//! Provider pricing tables, including cache-read / cache-write rates.

use std::collections::BTreeMap;

use falk_config::ProviderPricing;
use rust_decimal::Decimal;

use crate::usage::UsageEvent;

const MILLION: i64 = 1_000_000;

/// Estimate USD from token counts and the configured per-million rates.
pub fn estimate_usd(event: &UsageEvent, providers: &BTreeMap<String, ProviderPricing>) -> Decimal {
    let pricing = lookup_pricing(
        event.provider.as_deref(),
        event.model_id.as_deref(),
        providers,
    );
    let million = Decimal::from(MILLION);
    let input = Decimal::from(event.prompt_tokens) / million * pricing.input_per_mtok;
    let output = Decimal::from(event.completion_tokens) / million * pricing.output_per_mtok;
    let cache_r = Decimal::from(event.cache_read_tokens) / million * pricing.cache_read_per_mtok;
    let cache_w = Decimal::from(event.cache_write_tokens) / million * pricing.cache_write_per_mtok;
    input + output + cache_r + cache_w
}

/// Resolve a pricing row. Tries `provider/model`, then `provider`, then
/// a conservative default (openai-like).
pub fn lookup_pricing(
    provider: Option<&str>,
    model: Option<&str>,
    providers: &BTreeMap<String, ProviderPricing>,
) -> ProviderPricing {
    if let (Some(p), Some(m)) = (provider, model) {
        let key = format!("{p}/{m}");
        if let Some(row) = providers.get(&key) {
            return row.clone();
        }
        if let Some(row) = providers.get(m) {
            return row.clone();
        }
    }
    if let Some(p) = provider {
        if let Some(row) = providers.get(p) {
            return row.clone();
        }
    }
    providers.get("openai").cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use falk_config::FinopsConfig;
    use std::str::FromStr;

    #[test]
    fn cache_pricing_is_applied() {
        let cfg = FinopsConfig::default();
        let event = UsageEvent {
            provider: Some("anthropic".into()),
            model_id: Some("claude-sonnet-4".into()),
            prompt_tokens: 1_000_000,
            completion_tokens: 1_000_000,
            cache_read_tokens: 1_000_000,
            cache_write_tokens: 0,
            provider_cost_usd: None,
            estimated: true,
        };
        let usd = estimate_usd(&event, &cfg.providers);
        // 3.00 + 15.00 + 0.30 = 18.30
        assert_eq!(usd, Decimal::from_str("18.30").unwrap());
    }
}
