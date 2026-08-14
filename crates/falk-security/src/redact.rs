//! Streaming secret redaction with a hold-back window.
//!
//! Standalone mode uses typed markers (`[REDACTED:token]`, …).
//! Svärm mode mirrors `Svarm.Redact` in svarm-dev/svarm `lib/svarm/redact.ex`:
//! `[redacted]`, `[redacted pem]`, `KEY=[redacted]`, `Bearer [redacted]`,
//! `Authorization: …[redacted]`.

use std::sync::OnceLock;

use regex::Regex;

/// Replacement style. Svärm mode must stay byte-compatible with Svarm.Redact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactStyle {
    /// Typed markers for a human watching a standalone session.
    Standalone,
    /// `Svarm.Redact` replacement strings.
    Svarm,
}

impl RedactStyle {
    pub fn for_svarm(svarm: bool) -> Self {
        if svarm { Self::Svarm } else { Self::Standalone }
    }
}

struct Patterns {
    pem: Regex,
    env_names: Regex,
    authorization: Regex,
    bearer: Regex,
    token_shapes: Regex,
    jwt: Regex,
}

fn patterns() -> &'static Patterns {
    static PATS: OnceLock<Patterns> = OnceLock::new();
    PATS.get_or_init(|| Patterns {
        pem: Regex::new(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        )
        .expect("pem regex"),
        env_names: Regex::new(
            r#"\b((?:[A-Z][A-Z0-9_]*_)?(?:API_KEY|SECRET_ACCESS_KEY|ACCESS_KEY|PRIVATE_KEY|PASSWORD|SECRET|TOKEN)|SECRET_KEY_BASE)=(?:"[^"\n]*"|'[^'\n]*'|[^\s\n"']+)"#,
        )
        .expect("env regex"),
        authorization: Regex::new(r"(?i)(\bAuthorization:\s*)([^\n\r]+)").expect("auth regex"),
        bearer: Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]{8,}=*").expect("bearer regex"),
        token_shapes: Regex::new(
            r"\b(?:sk-or-v1-[A-Za-z0-9_\-]{8,}|sk-ant-[A-Za-z0-9_\-]{8,}|sk-proj-[A-Za-z0-9_\-]{8,}|sk-[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{8,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|ghu_[A-Za-z0-9]{20,}|ghs_[A-Za-z0-9]{20,}|ghr_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_\-]{8,}|xox[bpas]-[A-Za-z0-9\-]{10,}|npm_[A-Za-z0-9]{20,}|pypi-[A-Za-z0-9_\-]{20,}|sk_live_[A-Za-z0-9]{10,}|sk_test_[A-Za-z0-9]{10,}|rk_live_[A-Za-z0-9]{10,}|rk_test_[A-Za-z0-9]{10,})",
        )
        .expect("token regex"),
        jwt: Regex::new(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
            .expect("jwt regex"),
    })
}

/// Redact a complete UTF-8 string. Shipped function; used by the streamer and tests.
pub fn redact_text(input: &str, style: RedactStyle) -> String {
    let p = patterns();
    let (pem, env, auth, bearer, token, jwt) = match style {
        RedactStyle::Svarm => (
            "[redacted pem]",
            "=${1}SKIP", // placeholder, see below
            "[redacted]",
            "Bearer [redacted]",
            "[redacted]",
            "[redacted]",
        ),
        RedactStyle::Standalone => (
            "[REDACTED:pem]",
            "=${1}SKIP",
            "[REDACTED:authorization]",
            "Bearer [REDACTED:bearer]",
            "[REDACTED:token]",
            "[REDACTED:jwt]",
        ),
    };
    let _ = env;

    let mut s = p.pem.replace_all(input, pem).into_owned();
    s = match style {
        RedactStyle::Svarm => p.env_names.replace_all(&s, "$1=[redacted]").into_owned(),
        RedactStyle::Standalone => p
            .env_names
            .replace_all(&s, "$1=[REDACTED:env]")
            .into_owned(),
    };
    s = match style {
        RedactStyle::Svarm => p
            .authorization
            .replace_all(&s, "${1}[redacted]")
            .into_owned(),
        RedactStyle::Standalone => p
            .authorization
            .replace_all(&s, "${1}[REDACTED:authorization]")
            .into_owned(),
    };
    let _ = (auth, bearer, token, jwt);
    s = p.bearer.replace_all(&s, bearer).into_owned();
    s = p.token_shapes.replace_all(&s, token).into_owned();
    s = p.jwt.replace_all(&s, jwt).into_owned();
    s
}

/// Streaming redactor with a hold-back window so secrets that span buffers
/// are still caught.
pub struct StreamingRedactor {
    pending: Vec<u8>,
    holdback: usize,
    style: RedactStyle,
    enabled: bool,
}

impl StreamingRedactor {
    pub fn new(style: RedactStyle, holdback: usize, enabled: bool) -> Self {
        Self {
            pending: Vec::new(),
            holdback: holdback.max(32),
            style,
            enabled,
        }
    }

    pub fn standalone(holdback: usize) -> Self {
        Self::new(RedactStyle::Standalone, holdback, true)
    }

    pub fn svarm(holdback: usize) -> Self {
        Self::new(RedactStyle::Svarm, holdback, true)
    }

    /// Ingest `chunk`. Returns bytes that are safe to emit to the user now.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        if !self.enabled {
            return chunk.to_vec();
        }
        self.pending.extend_from_slice(chunk);
        self.emit_safe()
    }

    /// Flush remaining bytes (end of stream). Always redact the tail.
    pub fn flush(&mut self) -> Vec<u8> {
        if !self.enabled {
            return std::mem::take(&mut self.pending);
        }
        let text = String::from_utf8_lossy(&self.pending);
        let redacted = redact_text(&text, self.style);
        self.pending.clear();
        redacted.into_bytes()
    }

    fn emit_safe(&mut self) -> Vec<u8> {
        let text = String::from_utf8_lossy(&self.pending);
        let redacted = redact_text(&text, self.style);
        if redacted != text {
            // A complete secret was matched. Emit the redacted form and reset
            // so we do not re-emit the original suffix later.
            self.pending.clear();
            return redacted.into_bytes();
        }
        if self.pending.len() > self.holdback {
            let emit_len = self.pending.len() - self.holdback;
            self.pending.drain(..emit_len).collect()
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn svarm_mode_matches_svarm_redact_replacements() {
        let sk = redact_text("token=sk-ant-abcdefghijk", RedactStyle::Svarm);
        assert!(sk.contains("[redacted]"), "{sk}");
        assert!(!sk.contains("sk-ant-abcdefghijk"), "{sk}");

        let env = redact_text("API_KEY=supersecretvalue", RedactStyle::Svarm);
        assert_eq!(env, "API_KEY=[redacted]");

        let bearer = redact_text(
            "Authorization line: Bearer abcdefghijklmnop",
            RedactStyle::Svarm,
        );
        assert!(bearer.contains("Bearer [redacted]"), "{bearer}");
        assert!(!bearer.contains("abcdefghijklmnop"), "{bearer}");

        let auth = redact_text("Authorization: Bearer abcdefghijklmnop", RedactStyle::Svarm);
        assert!(auth.contains("Authorization:"), "{auth}");
        assert!(auth.contains("[redacted]"), "{auth}");
        assert!(!auth.contains("abcdefghijklmnop"), "{auth}");
    }

    #[test]
    fn standalone_uses_typed_markers() {
        let s = redact_text("sk-ant-abcdefghijk", RedactStyle::Standalone);
        assert!(s.contains("[REDACTED:token]"), "{s}");
    }

    #[test]
    fn secret_split_across_two_buffers_is_redacted() {
        let mut r = StreamingRedactor::svarm(64);
        let a = r.push(b"prefix sk-ant-ABC");
        let b = r.push(b"DEFGH12 suffix");
        let c = r.flush();
        let all = [a, b, c].concat();
        let text = String::from_utf8_lossy(&all);
        assert!(!text.contains("sk-ant-"), "secret must not leak: {text:?}");
        assert!(
            text.contains("[redacted]"),
            "must use Svarm.Redact replacement: {text:?}"
        );
        assert!(text.contains("prefix"), "{text:?}");
        assert!(text.contains("suffix"), "{text:?}");
    }
}
