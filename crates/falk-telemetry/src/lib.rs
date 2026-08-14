//! NDJSON side-channel.
//!
//! In Svärm mode this is the **only** outbound control-plane surface. Events
//! never write Task fields `status`, `wait_reason`, `pending_question`, or
//! `attempts` — those belong exclusively to the Svärm Orchestrator.
//!
//! Incremental `usage` events map 1:1 onto `Svarm.Usage` / `Usage.Record`:
//! `run_id`, `task_id`, `provider`, `model_id`, token fields,
//! `provider_cost_usd`, `estimated`.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rust_decimal::Decimal;
use serde::Serialize;

/// A single NDJSON record. Field names for `usage` match Usage.Record.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Usage {
        run_id: String,
        task_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        provider: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        model_id: Option<String>,
        prompt_tokens: u64,
        completion_tokens: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_read_tokens: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_write_tokens: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        provider_cost_usd: Option<Decimal>,
        estimated: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        source: Option<String>,
    },
    Limit {
        kind: LimitKind,
        total_usd: Decimal,
        #[serde(skip_serializing_if = "Option::is_none")]
        ceiling_usd: Option<Decimal>,
    },
    Loop {
        reason: String,
        repeats: usize,
    },
    Security {
        verdict: String,
        reason: String,
    },
    Warn {
        component: String,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LimitKind {
    Soft,
    Hard,
    PromptTokens,
    CompletionTokens,
}

/// Where NDJSON is written. Never agent stdout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sink {
    Path(PathBuf),
    Fd(i32),
    /// In-memory sink used by tests of the shipped emitter.
    Buffer,
}

pub struct Emitter {
    sink: Sink,
    file: Mutex<Option<File>>,
    buffer: Mutex<Vec<String>>,
}

impl Emitter {
    pub fn new(sink: Sink) -> Result<Self, TelemetryError> {
        let file = match &sink {
            Sink::Path(path) => Some(File::create(path).map_err(|err| TelemetryError::Io {
                path: path.display().to_string(),
                message: err.to_string(),
            })?),
            Sink::Fd(fd) => {
                #[cfg(unix)]
                {
                    use std::os::fd::FromRawFd;
                    // SAFETY: the caller transfers this fd to the emitter for the
                    // process lifetime; File will close it on drop.
                    Some(unsafe { File::from_raw_fd(*fd) })
                }
                #[cfg(not(unix))]
                {
                    let _ = fd;
                    return Err(TelemetryError::Io {
                        path: "fd".into(),
                        message: "fd sink is unix-only".into(),
                    });
                }
            }
            Sink::Buffer => None,
        };
        Ok(Self {
            sink,
            file: Mutex::new(file),
            buffer: Mutex::new(Vec::new()),
        })
    }

    pub fn from_config(path: &str, fd: i32, svarm: bool) -> Result<Option<Self>, TelemetryError> {
        if !path.is_empty() {
            return Ok(Some(Self::new(Sink::Path(PathBuf::from(path)))?));
        }
        if fd > 0 {
            return Ok(Some(Self::new(Sink::Fd(fd))?));
        }
        if svarm {
            return Ok(Some(Self::new(Sink::Path(PathBuf::from(
                "falk-events.ndjson",
            )))?));
        }
        Ok(None)
    }

    /// Serialize and write one event. This is the shipped emit function.
    pub fn emit(&self, event: &Event) -> Result<String, TelemetryError> {
        let line = serialize_event(event)?;
        match &self.sink {
            Sink::Buffer => {
                self.buffer
                    .lock()
                    .expect("telemetry buffer lock")
                    .push(line.clone());
            }
            Sink::Path(_) | Sink::Fd(_) => {
                if let Some(file) = self.file.lock().expect("telemetry file lock").as_mut() {
                    writeln!(file, "{line}").map_err(|err| TelemetryError::Io {
                        path: format!("{:?}", self.sink),
                        message: err.to_string(),
                    })?;
                    file.flush().ok();
                }
            }
        }
        Ok(line)
    }

    pub fn emitted_lines(&self) -> Vec<String> {
        self.buffer.lock().expect("telemetry buffer lock").clone()
    }

    pub fn path(&self) -> Option<&Path> {
        match &self.sink {
            Sink::Path(p) => Some(p),
            _ => None,
        }
    }
}

/// Serialize one event as a single NDJSON object (no trailing newline).
pub fn serialize_event(event: &Event) -> Result<String, TelemetryError> {
    serde_json::to_string(event).map_err(|err| TelemetryError::Serialize(err.to_string()))
}

#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("failed to write NDJSON to {path}: {message}")]
    Io { path: String, message: String },
    #[error("failed to serialize event: {0}")]
    Serialize(String),
}

/// Incremental Usage.Record-shaped NDJSON event. Called once per parsed
/// stream usage event (not only on hard-limit).
pub fn usage_record(
    run_id: impl Into<String>,
    task_id: impl Into<String>,
    provider: Option<String>,
    model_id: Option<String>,
    prompt_tokens: u64,
    completion_tokens: u64,
    cache_read_tokens: u64,
    cache_write_tokens: u64,
    provider_cost_usd: Option<Decimal>,
    estimated: bool,
) -> Event {
    Event::Usage {
        run_id: run_id.into(),
        task_id: task_id.into(),
        provider,
        model_id,
        prompt_tokens,
        completion_tokens,
        cache_read_tokens: (cache_read_tokens > 0).then_some(cache_read_tokens),
        cache_write_tokens: (cache_write_tokens > 0).then_some(cache_write_tokens),
        provider_cost_usd,
        estimated,
        source: Some("falk".into()),
    }
}

/// Convenience wrapper used by tests that do not care about cache tokens.
pub fn usage_event(
    run_id: impl Into<String>,
    task_id: impl Into<String>,
    provider: Option<String>,
    model_id: Option<String>,
    prompt_tokens: u64,
    completion_tokens: u64,
    provider_cost_usd: Option<Decimal>,
    estimated: bool,
) -> Event {
    usage_record(
        run_id,
        task_id,
        provider,
        model_id,
        prompt_tokens,
        completion_tokens,
        0,
        0,
        provider_cost_usd,
        estimated,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal::Decimal;
    use std::str::FromStr;

    fn dec(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    #[test]
    fn usage_ndjson_has_usage_record_fields() {
        let emitter = Emitter::new(Sink::Buffer).unwrap();
        let event = usage_event(
            "run-1",
            "task-9",
            Some("anthropic".into()),
            Some("claude-sonnet-4".into()),
            12,
            34,
            Some(dec("0.042")),
            false,
        );
        let line = emitter.emit(&event).unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["event"], "usage");
        assert_eq!(v["run_id"], "run-1");
        assert_eq!(v["task_id"], "task-9");
        assert_eq!(v["provider"], "anthropic");
        assert_eq!(v["model_id"], "claude-sonnet-4");
        assert_eq!(v["prompt_tokens"], 12);
        assert_eq!(v["completion_tokens"], 34);
        assert_eq!(v["provider_cost_usd"], "0.042");
        assert_eq!(v["estimated"], false);
        // Dual-identity: we must never emit orchestrator-owned Task fields.
        assert!(v.get("status").is_none());
        assert!(v.get("wait_reason").is_none());
        assert!(v.get("pending_question").is_none());
        assert!(v.get("attempts").is_none());
    }

    #[test]
    fn write_to_path_roundtrip() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("falk-tel-{}.ndjson", std::process::id()));
        let emitter = Emitter::new(Sink::Path(path.clone())).unwrap();
        emitter
            .emit(&Event::Warn {
                component: "test".into(),
                message: "hello".into(),
            })
            .unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(body.contains("\"event\":\"warn\""));
        assert!(body.contains("hello"));
    }
}
