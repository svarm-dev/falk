//! rust_decimal USD (and optional token) accumulator.

use falk_config::FinopsConfig;
use rust_decimal::Decimal;

use crate::usage::UsageEvent;

#[derive(Debug, Clone, PartialEq)]
pub enum LimitDecision {
    SoftWarn { total_usd: Decimal, limit: Decimal },
    HardKill { total_usd: Decimal, limit: Decimal },
    PromptTokens { total: u64, limit: u64 },
    CompletionTokens { total: u64, limit: u64 },
    Loop { reason: String, repeats: usize },
}

impl LimitDecision {
    pub fn is_hard_kill(&self) -> bool {
        matches!(
            self,
            Self::HardKill { .. }
                | Self::PromptTokens { .. }
                | Self::CompletionTokens { .. }
                | Self::Loop { .. }
        )
    }

    pub fn is_soft_warn(&self) -> bool {
        matches!(self, Self::SoftWarn { .. })
    }
}

#[derive(Debug, Clone)]
pub struct CostAccumulator {
    pub total_usd: Decimal,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    soft: Option<Decimal>,
    hard: Option<Decimal>,
    max_prompt: u64,
    max_completion: u64,
    soft_fired: bool,
}

impl CostAccumulator {
    pub fn new(
        soft: Option<Decimal>,
        hard: Option<Decimal>,
        max_prompt: u64,
        max_completion: u64,
    ) -> Self {
        Self {
            total_usd: Decimal::ZERO,
            prompt_tokens: 0,
            completion_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            soft,
            hard,
            max_prompt,
            max_completion,
            soft_fired: false,
        }
    }

    pub fn from_config(cfg: &FinopsConfig) -> Self {
        Self::new(
            cfg.soft_limit_usd,
            cfg.hard_limit_usd,
            cfg.max_prompt_tokens,
            cfg.max_completion_tokens,
        )
    }

    /// Add a usage event and return a decision if a ceiling was crossed.
    /// Soft limit only warns (once). Hard limit requests killpg.
    pub fn apply(&mut self, event: &UsageEvent) -> Option<LimitDecision> {
        if let Some(cost) = event.provider_cost_usd {
            self.total_usd += cost;
        }
        self.prompt_tokens = self.prompt_tokens.saturating_add(event.prompt_tokens);
        self.completion_tokens = self
            .completion_tokens
            .saturating_add(event.completion_tokens);
        self.cache_read_tokens = self
            .cache_read_tokens
            .saturating_add(event.cache_read_tokens);
        self.cache_write_tokens = self
            .cache_write_tokens
            .saturating_add(event.cache_write_tokens);

        if self.max_prompt > 0 && self.prompt_tokens >= self.max_prompt {
            return Some(LimitDecision::PromptTokens {
                total: self.prompt_tokens,
                limit: self.max_prompt,
            });
        }
        if self.max_completion > 0 && self.completion_tokens >= self.max_completion {
            return Some(LimitDecision::CompletionTokens {
                total: self.completion_tokens,
                limit: self.max_completion,
            });
        }
        if let Some(hard) = self.hard {
            if self.total_usd >= hard {
                return Some(LimitDecision::HardKill {
                    total_usd: self.total_usd,
                    limit: hard,
                });
            }
        }
        if let Some(soft) = self.soft {
            if !self.soft_fired && self.total_usd >= soft {
                self.soft_fired = true;
                return Some(LimitDecision::SoftWarn {
                    total_usd: self.total_usd,
                    limit: soft,
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usage::UsageEvent;
    use std::str::FromStr;

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    fn usd(s: &str) -> UsageEvent {
        UsageEvent {
            provider: Some("openai".into()),
            model_id: Some("gpt-4o".into()),
            prompt_tokens: 10,
            completion_tokens: 5,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            provider_cost_usd: Some(dec(s)),
            estimated: false,
        }
    }

    #[test]
    fn rust_decimal_adds_without_float() {
        let mut acc = CostAccumulator::new(None, Some(dec("1.00")), 0, 0);
        acc.apply(&usd("0.40"));
        acc.apply(&usd("0.40"));
        assert_eq!(acc.total_usd, dec("0.80"));
        let hit = acc.apply(&usd("0.20")).unwrap();
        assert!(matches!(hit, LimitDecision::HardKill { .. }));
        assert_eq!(acc.total_usd, dec("1.00"));
    }

    #[test]
    fn soft_then_hard() {
        let mut acc = CostAccumulator::new(Some(dec("0.50")), Some(dec("1.00")), 0, 0);
        let soft = acc.apply(&usd("0.60")).unwrap();
        assert!(soft.is_soft_warn());
        assert!(!soft.is_hard_kill());
        let hard = acc.apply(&usd("0.50")).unwrap();
        assert!(hard.is_hard_kill());
    }
}
