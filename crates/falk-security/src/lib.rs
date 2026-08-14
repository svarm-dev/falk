//! Security engine: hybrid candidates (PTY lines + `tool_use` / `function-call`
//! JSON), fail-closed tree-sitter-bash walk, policy, streaming redaction.
//!
//! This crate is a **subscriber**. It must never gate the PTY passthrough hot
//! path. The runtime fans bytes out; we evaluate asynchronously and return a
//! [`Verdict`]. Interpreters themselves are not blanket-blocked — nested
//! `bash -c` / `eval` arguments are re-parsed.

pub mod ast;
pub mod candidates;
pub mod policy;
pub mod redact;

pub use ast::{WalkFinding, WalkOutcome, walk_bash};
pub use candidates::{Candidate, extract_candidates};
pub use policy::{evaluate_policy, evaluate_script};
pub use redact::{RedactStyle, StreamingRedactor, redact_text};

use falk_config::{EnforcementMode, SecurityConfig};

/// Outcome after combining a finding (if any) with the configured enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Warn { reason: String },
    Block { reason: String },
    Kill { reason: String },
}

impl Verdict {
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Allow => None,
            Self::Warn { reason } | Self::Block { reason } | Self::Kill { reason } => {
                Some(reason.as_str())
            }
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn { .. } => "warn",
            Self::Block { .. } => "block",
            Self::Kill { .. } => "kill",
        }
    }
}

/// Map a policy finding through the configured enforcement mode.
///
/// `Warn` / `Block` / `Kill` modes produce different [`Verdict`]s for the
/// same finding — this is the shipped function tests use to prove they differ.
pub fn apply_enforcement(mode: EnforcementMode, finding: Option<&str>) -> Verdict {
    match finding {
        None => Verdict::Allow,
        Some(reason) => match mode {
            EnforcementMode::Warn => Verdict::Warn {
                reason: reason.to_string(),
            },
            EnforcementMode::Block => Verdict::Block {
                reason: reason.to_string(),
            },
            EnforcementMode::Kill => Verdict::Kill {
                reason: reason.to_string(),
            },
        },
    }
}

/// Evaluate one candidate script against `cfg` and return a verdict.
pub fn inspect_script(script: &str, cfg: &SecurityConfig) -> Verdict {
    let finding = evaluate_script(script, cfg);
    apply_enforcement(cfg.enforcement, finding.as_deref())
}

/// Evaluate hybrid candidates extracted from a stream chunk.
pub fn inspect_chunk(chunk: &str, cfg: &SecurityConfig) -> Verdict {
    let cands = extract_candidates(chunk);
    for cand in &cands {
        let finding = evaluate_policy(cand, cfg);
        if let Some(reason) = finding {
            return apply_enforcement(cfg.enforcement, Some(reason.as_str()));
        }
    }
    Verdict::Allow
}

#[cfg(test)]
mod tests {
    use super::*;
    use falk_config::SecurityConfig;

    #[test]
    fn enforcement_modes_differ() {
        let reason = "blocked command `rm`";
        assert!(matches!(
            apply_enforcement(EnforcementMode::Warn, Some(reason)),
            Verdict::Warn { .. }
        ));
        assert!(matches!(
            apply_enforcement(EnforcementMode::Block, Some(reason)),
            Verdict::Block { .. }
        ));
        assert!(matches!(
            apply_enforcement(EnforcementMode::Kill, Some(reason)),
            Verdict::Kill { .. }
        ));
        assert_eq!(
            apply_enforcement(EnforcementMode::Kill, None),
            Verdict::Allow
        );
    }

    #[test]
    fn default_echo_is_allowed() {
        let cfg = SecurityConfig::default();
        assert_eq!(inspect_script("echo hello", &cfg), Verdict::Allow);
    }
}
