//! FinOps engine: rust_decimal USD accumulator, provider usage parsers,
//! sliding-window loop detector, soft-warn / hard-kill decisions.
//!
//! Non-blocking subscriber. Hard kill is *decided* here and *executed* only
//! by [`falk_pty::Supervisor::kill_tree`] (`killpg(SIGTERM)` → grace →
//! `killpg(SIGKILL)`). That is the mid-run gap Svärm Budget (preflight-only)
//! does not cover.

pub mod cost;
pub mod loop_detect;
pub mod pricing;
pub mod usage;

pub use cost::{CostAccumulator, LimitDecision};
pub use loop_detect::{LoopDetector, LoopSample, LoopTrip};
pub use pricing::{estimate_usd, lookup_pricing};
pub use usage::{UsageEvent, parse_usage_events};

/// Result of ingesting one stream chunk: priced usage events (for incremental
/// NDJSON / Usage.Record) plus any soft/hard/loop decisions.
#[derive(Debug, Default, Clone)]
pub struct IngestOutcome {
    pub events: Vec<UsageEvent>,
    pub decisions: Vec<LimitDecision>,
}

use falk_config::FinopsConfig;
use rust_decimal::Decimal;

/// Combined subscriber state.
pub struct FinopsEngine {
    pub cost: CostAccumulator,
    pub loops: LoopDetector,
}

impl FinopsEngine {
    pub fn from_config(cfg: &FinopsConfig) -> Self {
        Self {
            cost: CostAccumulator::from_config(cfg),
            loops: LoopDetector::from_config(&cfg.loop_detect),
        }
    }

    pub fn ingest_chunk(&mut self, chunk: &str, cfg: &FinopsConfig) -> IngestOutcome {
        let mut outcome = IngestOutcome::default();
        for event in parse_usage_events(chunk) {
            let priced = if event.provider_cost_usd.is_some() {
                event
            } else if cfg.estimator {
                let est = estimate_usd(&event, &cfg.providers);
                UsageEvent {
                    provider_cost_usd: Some(est),
                    estimated: true,
                    ..event
                }
            } else {
                event
            };
            if let Some(d) = self.cost.apply(&priced) {
                outcome.decisions.push(d);
            }
            outcome.events.push(priced);
        }
        if let Some(trip) = self.loops.observe_chunk(chunk) {
            outcome.decisions.push(LimitDecision::Loop {
                reason: trip.reason,
                repeats: trip.repeats,
            });
        }
        outcome
    }
}

pub fn parse_decimal(s: &str) -> Option<Decimal> {
    s.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use falk_config::FinopsConfig;
    use rust_decimal::Decimal;
    use std::str::FromStr;
    use std::time::Duration;

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    #[test]
    fn hard_ceiling_invokes_supervisor_killpg() {
        let mut acc = CostAccumulator::new(Some(dec("0.50")), Some(dec("1.00")), 0, 0);
        let event = UsageEvent {
            provider: Some("anthropic".into()),
            model_id: Some("claude-sonnet-4".into()),
            prompt_tokens: 0,
            completion_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            provider_cost_usd: Some(dec("1.50")),
            estimated: false,
        };
        let decision = acc.apply(&event).expect("hard decision");
        assert!(
            matches!(decision, LimitDecision::HardKill { .. }),
            "{decision:?}"
        );

        // Drive the shipped supervisor killpg path against a real child group.
        // trap ignores SIGTERM in the shell; the loop keeps the leader alive
        // after `sleep` (which does not ignore TERM) is signalled.
        let args = [
            "/bin/sh",
            "-c",
            "trap '' TERM; printf 'READY\\n'; while true; do sleep 1; done",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        let mut sup = falk_pty::Supervisor::spawn(&args, falk_pty::Size::fallback())
            .expect("spawn sleep tree");
        {
            let mut reader = sup.try_clone_reader().expect("reader");
            let mut buf = [0u8; 64];
            let mut got = String::new();
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while std::time::Instant::now() < deadline {
                if let Ok(n) = std::io::Read::read(&mut reader, &mut buf) {
                    got.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if got.contains("READY") {
                        break;
                    }
                }
            }
            assert!(
                got.contains("READY"),
                "child must install trap first: {got:?}"
            );
        }
        assert!(matches!(decision, LimitDecision::HardKill { .. }));
        let report = sup
            .kill_tree(Duration::from_millis(250))
            .expect("kill_tree");
        assert!(report.term_sent);
        assert!(report.kill_sent, "SIGKILL after grace: {report:?}");
        let _ = sup.wait();
    }

    #[test]
    fn soft_ceiling_does_not_kill() {
        let mut acc = CostAccumulator::new(Some(dec("0.10")), Some(dec("9.00")), 0, 0);
        let event = UsageEvent {
            provider: None,
            model_id: None,
            prompt_tokens: 0,
            completion_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            provider_cost_usd: Some(dec("0.25")),
            estimated: false,
        };
        let decision = acc.apply(&event).expect("soft");
        assert!(matches!(decision, LimitDecision::SoftWarn { .. }));
        assert!(!decision.is_hard_kill());
    }

    #[test]
    fn ingest_chunk_returns_priced_usage_events() {
        let cfg = FinopsConfig::default();
        let mut engine = FinopsEngine::from_config(&cfg);
        let chunk = r#"{"provider":"anthropic","model_id":"claude-sonnet-4","usage":{"input_tokens":12,"output_tokens":34},"provider_cost_usd":"0.042"}"#;
        let outcome = engine.ingest_chunk(chunk, &cfg);
        assert_eq!(outcome.events.len(), 1, "{outcome:?}");
        let ev = &outcome.events[0];
        assert_eq!(ev.provider.as_deref(), Some("anthropic"));
        assert_eq!(ev.model_id.as_deref(), Some("claude-sonnet-4"));
        assert_eq!(ev.prompt_tokens, 12);
        assert_eq!(ev.completion_tokens, 34);
        assert_eq!(ev.provider_cost_usd, Some(dec("0.042")));
        assert!(!ev.estimated);
        assert!(outcome.decisions.is_empty());
    }

    #[test]
    fn loop_window_trips_on_repeated_fingerprint() {
        let cfg = FinopsConfig::default();
        let mut det = LoopDetector::from_config(&cfg.loop_detect);
        let mut tripped = None;
        for _ in 0..cfg.loop_detect.repeat_threshold {
            tripped = det.observe(LoopSample {
                command_fp: 0xabc,
                output_hash: 0xdef,
                failed: true,
            });
        }
        assert!(tripped.is_some(), "sliding window must trip");
    }

    #[test]
    fn ingest_identical_error_without_command_does_not_loop_kill() {
        let cfg = FinopsConfig::default();
        let mut engine = FinopsEngine::from_config(&cfg);
        let mut last = None;
        for _ in 0..cfg.loop_detect.repeat_threshold {
            let outcome = engine.ingest_chunk("Error: retry\n", &cfg);
            last = outcome
                .decisions
                .into_iter()
                .find(|d| matches!(d, LimitDecision::Loop { .. }));
        }
        assert!(
            last.is_none(),
            "command_fp == 0 must not hard-kill: {last:?}"
        );

        engine.loops.note_command("cat /etc/shadow");
        let mut tripped = None;
        for _ in 0..cfg.loop_detect.repeat_threshold {
            let outcome = engine.ingest_chunk("Error: retry\n", &cfg);
            tripped = outcome
                .decisions
                .into_iter()
                .find(|d| matches!(d, LimitDecision::Loop { .. }));
        }
        assert!(
            tripped.is_some(),
            "repeated failed command fingerprint must still trip"
        );
    }

    #[test]
    fn ingest_prose_then_repeated_errors_does_not_loop_kill() {
        let cfg = FinopsConfig::default();
        let mut engine = FinopsEngine::from_config(&cfg);
        let _ = engine.ingest_chunk("I'll retry that approach now.\n", &cfg);
        let mut last = None;
        for _ in 0..cfg.loop_detect.repeat_threshold {
            let outcome = engine.ingest_chunk("Error: retry\n", &cfg);
            last = outcome
                .decisions
                .into_iter()
                .find(|d| matches!(d, LimitDecision::Loop { .. }));
        }
        assert!(
            last.is_none(),
            "agent prose must not become a command fingerprint: {last:?}"
        );
    }
}
