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
    /// True after we have seen an unmatched private-key BEGIN. Stays set
    /// after the header is emitted by the 16 KiB cap so the body is still held.
    holding_private_key: bool,
}

impl StreamingRedactor {
    pub fn new(style: RedactStyle, holdback: usize, enabled: bool) -> Self {
        Self {
            pending: Vec::new(),
            holdback: holdback.max(32),
            style,
            enabled,
            holding_private_key: false,
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
            self.holding_private_key = false;
            return std::mem::take(&mut self.pending);
        }
        let text = String::from_utf8_lossy(&self.pending);
        let redacted = redact_text(&text, self.style);
        self.pending.clear();
        self.holding_private_key = false;
        redacted.into_bytes()
    }

    fn emit_safe(&mut self) -> Vec<u8> {
        let text = String::from_utf8_lossy(&self.pending);
        let redacted = redact_text(&text, self.style);
        if redacted != text {
            // A complete secret was matched. Emit the redacted form and reset
            // so we do not re-emit the original suffix later.
            self.pending.clear();
            self.holding_private_key = false;
            return redacted.into_bytes();
        }
        if open_pem_start(&self.pending).is_some() {
            self.holding_private_key = true;
        }
        let emit_len = safe_emit_len_for_hold(
            &self.pending,
            self.holdback,
            self.holding_private_key,
        );
        let out = if emit_len > 0 {
            self.pending.drain(..emit_len).collect()
        } else {
            Vec::new()
        };
        if has_end_private_key(&self.pending) && open_pem_start(&self.pending).is_none() {
            self.holding_private_key = false;
        }
        out
    }
}

/// Max bytes held after an unmatched private-key BEGIN (covers a 4096-bit PEM).
const PEM_HOLD_CAP: usize = 16 * 1024;
const PEM_BEGIN: &[u8] = b"-----BEGIN ";
const PEM_END: &[u8] = b"-----END ";
const PRIVATE_KEY: &[u8] = b"PRIVATE KEY";

/// How many leading pending bytes are safe to emit. Shipped so tests drive
/// the same hold-back rule as `StreamingRedactor::push`.
pub fn safe_emit_len(pending: &[u8], holdback: usize) -> usize {
    let holding = open_pem_start(pending).is_some();
    safe_emit_len_for_hold(pending, holdback, holding)
}

/// `holding_private_key` stays true after a cap overflow has already emitted
/// the BEGIN header, so the remaining body is still held to `PEM_HOLD_CAP`.
pub fn safe_emit_len_for_hold(pending: &[u8], holdback: usize, holding_private_key: bool) -> usize {
    let holdback = holdback.max(32);
    let normal = pending.len().saturating_sub(holdback);
    match open_pem_start(pending) {
        Some(start) if pending.len() - start > PEM_HOLD_CAP => pending.len() - PEM_HOLD_CAP,
        Some(start) => start.min(normal),
        None if holding_private_key => pending.len().saturating_sub(PEM_HOLD_CAP),
        None => normal,
    }
}

/// Offset of the last unmatched `BEGIN … PRIVATE KEY` header, if any.
fn open_pem_start(buf: &[u8]) -> Option<usize> {
    let mut last_open = None;
    let mut search = 0;
    while let Some(rel) = find_bytes(&buf[search..], PEM_BEGIN) {
        let start = search + rel;
        let header = header_line(buf, start);
        search = start + PEM_BEGIN.len();
        if find_bytes(header, PRIVATE_KEY).is_none() {
            continue;
        }
        if !has_end_private_key(&buf[start..]) {
            last_open = Some(start);
        }
    }
    last_open
}

fn header_line(buf: &[u8], start: usize) -> &[u8] {
    let rest = &buf[start..];
    let end = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
    &rest[..end]
}

fn has_end_private_key(buf: &[u8]) -> bool {
    let mut search = 0;
    while let Some(rel) = find_bytes(&buf[search..], PEM_END) {
        let at = search + rel;
        if find_bytes(header_line(buf, at), PRIVATE_KEY).is_some() {
            return true;
        }
        search = at + PEM_END.len();
    }
    false
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
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

    #[test]
    fn pem_split_across_push_does_not_leak_begin() {
        let mut body = b"-----BEGIN RSA PRIVATE KEY-----\n".to_vec();
        body.extend(std::iter::repeat_n(b'A', 600));
        assert!(
            body.len() > 512,
            "first chunk must exceed default hold-back"
        );
        assert!(
            !body.windows(b"-----END ".len()).any(|w| w == b"-----END "),
            "first chunk must not contain END"
        );

        let mut r = StreamingRedactor::svarm(512);
        let first = r.push(&body);
        let first_text = String::from_utf8_lossy(&first);
        assert!(
            !first_text.contains("BEGIN"),
            "open PEM must stay in the hold window: {first_text:?}"
        );

        let second = r.push(b"\n-----END RSA PRIVATE KEY-----\n");
        let tail = r.flush();
        let all = [first, second, tail].concat();
        let text = String::from_utf8_lossy(&all);
        assert!(
            !text.contains("BEGIN RSA"),
            "PEM body must not leak: {text:?}"
        );
        assert!(
            text.contains("[redacted pem]"),
            "must use Svarm.Redact PEM replacement: {text:?}"
        );
    }

    #[test]
    fn open_pem_past_cap_emits_oldest_bytes() {
        let mut body = b"-----BEGIN RSA PRIVATE KEY-----\n".to_vec();
        body.extend(std::iter::repeat_n(b'A', PEM_HOLD_CAP + 200));
        let emit = safe_emit_len(&body, 512);
        assert!(
            emit > 0,
            "cap must release bytes so pending does not grow forever"
        );
        assert_eq!(emit, body.len() - PEM_HOLD_CAP);

        let mut r = StreamingRedactor::svarm(512);
        let visible = r.push(&body);
        assert!(
            !visible.is_empty(),
            "StreamingRedactor::push must emit past the cap"
        );
    }

    #[test]
    fn second_push_after_cap_still_holds_key_body() {
        let mut body = b"-----BEGIN RSA PRIVATE KEY-----\n".to_vec();
        body.extend(std::iter::repeat_n(b'A', PEM_HOLD_CAP + 200));
        let mut r = StreamingRedactor::svarm(512);
        let first = r.push(&body);
        assert!(!first.is_empty(), "first push must release past the cap");

        let marker = b"SECONDPUSHKEYBODY";
        let second = r.push(marker);
        let second_text = String::from_utf8_lossy(&second);
        assert!(
            !second_text.contains("SECONDPUSHKEYBODY"),
            "remaining key body must stay held after BEGIN was drained: {second_text:?}"
        );
        let without_begin = body[b"-----BEGIN RSA PRIVATE KEY-----\n".len()..].to_vec();
        let dumped = safe_emit_len_for_hold(&without_begin, 512, false);
        assert!(
            dumped > PEM_HOLD_CAP / 2,
            "without the hold flag the body would dump under normal holdback"
        );
        assert_eq!(
            safe_emit_len_for_hold(&without_begin, 512, true),
            without_begin.len().saturating_sub(PEM_HOLD_CAP)
        );
    }

    #[test]
    fn complete_cert_does_not_release_incomplete_private_key() {
        let mut buf = b"-----BEGIN CERTIFICATE-----\nCERTDATA\n-----END CERTIFICATE-----\n-----BEGIN RSA PRIVATE KEY-----\n".to_vec();
        buf.extend(std::iter::repeat_n(b'B', 600));
        let emit = safe_emit_len(&buf, 512);
        let visible = &buf[..emit];
        let text = String::from_utf8_lossy(visible);
        assert!(
            !text.contains("PRIVATE KEY"),
            "incomplete private key must stay held after a closed cert: {text:?}"
        );
        assert!(
            !text.contains("BEGIN RSA"),
            "key header must not leak: {text:?}"
        );

        let mut r = StreamingRedactor::svarm(512);
        let first = r.push(&buf);
        let first_text = String::from_utf8_lossy(&first);
        assert!(
            !first_text.contains("PRIVATE KEY"),
            "push must not emit key body: {first_text:?}"
        );
        assert!(
            !first_text.contains("BBBB"),
            "key body must not leak: {first_text:?}"
        );
    }
}
