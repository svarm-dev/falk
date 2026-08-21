//! Runtime loop: PTY read → fan-out.
//!
//! Hot path: streaming redactor → user stdout. Never waits on AST or cost.
//! Security and FinOps are independent subscribers on their own threads.

use std::io::{self, Read, Write};
use std::process::ExitCode;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::claude_jsonl::{is_claude_command, jsonl_watch_enabled, spawn_tailer};
use anyhow::Context;
use falk_config::{Config, Mode};
use falk_finops::{FinopsEngine, LimitDecision, UsageEvent};
use falk_pty::signals::{SignalKind, forwarded_signal_for};
use falk_pty::terminal::{TerminalGuard, detect_size};
use falk_pty::{Size, Supervisor};
use falk_security::redact::{RedactStyle, StreamingRedactor};
use falk_security::{Verdict, inspect_chunk};
use falk_telemetry::{Emitter, Event, LimitKind, usage_record};
use tracing::{debug, warn};

#[derive(Debug)]
enum Action {
    Kill { reason: String },
    Block { reason: String },
    Warn { message: String },
}

/// Map a security verdict onto a runtime action. Shipped so Block stays
/// distinct from Warn (issue #11).
fn action_from_verdict(verdict: Verdict) -> Option<Action> {
    match verdict {
        Verdict::Allow => None,
        Verdict::Warn { reason } => Some(Action::Warn {
            message: format!("security: {reason}"),
        }),
        Verdict::Block { reason } => Some(Action::Block { reason }),
        Verdict::Kill { reason } => Some(Action::Kill {
            reason: format!("security: {reason}"),
        }),
    }
}

pub fn run_wrapped(argv: &[String], cfg: &Config) -> anyhow::Result<ExitCode> {
    // Dual identity: standalone is the default and fully useful alone.
    // Svärm is an additive runtime switch — never a compile-time Svärm/Elixir dep.
    let mode = cfg.effective_mode();
    let svarm = mode == Mode::Svarm;
    // Consume SIGINT/SIGTERM/SIGWINCH in our waiter so they do not kill falk
    // before we can forward them to the child's process group.
    block_parent_signals();

    // Standalone + TTY → raw mode. Svärm / piped stdin stay cooked so the
    // outer interface is Port.open-compatible. SIGWINCH cannot cross a Port.
    let raw = cfg.pty.raw_mode && !svarm;
    let _term = TerminalGuard::acquire(raw).context("terminal raw mode")?;

    let size = detect_size(cfg.pty.rows, cfg.pty.cols);
    let mut supervisor = Supervisor::spawn(argv, size).context("open PTY / spawn child")?;
    debug!(
        pid = supervisor.pid(),
        pgid = supervisor.pgid(),
        ?mode,
        "spawned child as session+pgroup leader"
    );

    let emitter = Emitter::from_config(&cfg.svarm.ndjson_path, cfg.svarm.ndjson_fd, svarm)
        .context("open NDJSON side-channel")?;
    let emitter = emitter.map(Arc::new);

    let (action_tx, action_rx) = mpsc::channel::<Action>();
    let (byte_tx, byte_rx) = mpsc::channel::<Vec<u8>>();

    let mut reader = supervisor.try_clone_reader().context("clone PTY reader")?;
    let reader_thread = thread::Builder::new()
        .name("falk-pty-read".into())
        .spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if byte_tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        })
        .context("spawn reader")?;

    // stdin → PTY. In Svärm mode this is the Port.open pipe.
    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>();
    let stdin_pump = thread::Builder::new()
        .name("falk-stdin".into())
        .spawn(move || {
            let mut stdin = io::stdin();
            let mut buf = [0u8; 4096];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if in_tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
        })
        .context("spawn stdin")?;

    run_event_loop(
        &mut supervisor,
        cfg,
        svarm,
        size,
        byte_rx,
        in_rx,
        action_tx,
        action_rx,
        emitter.as_ref(),
        is_claude_command(argv) && jsonl_watch_enabled(),
    )?;

    finish_io_threads(reader_thread, Some(stdin_pump));

    let exit = match supervisor.try_wait()? {
        Some(st) => st,
        None => supervisor.wait()?,
    };
    Ok(exit.as_exit_code())
}

/// Join helpers that unblock when the child exits. **Never join the stdin
/// pump**: a parent TTY or Svärm `Port.open` keeps stdin open, so
/// `stdin.read` would never return and falk would hang (child status lost).
/// Dropping the `JoinHandle` detaches that thread.
pub fn finish_io_threads(
    pty_reader: thread::JoinHandle<()>,
    stdin_pump: Option<thread::JoinHandle<()>>,
) {
    let _ = pty_reader.join();
    drop(stdin_pump);
}

/// Map a priced FinOps usage event onto the Usage.Record NDJSON shape.
pub fn usage_ndjson(run_id: &str, task_id: &str, event: &UsageEvent) -> Event {
    usage_record(
        run_id,
        task_id,
        event.provider.clone(),
        event.model_id.clone(),
        event.prompt_tokens,
        event.completion_tokens,
        event.cache_read_tokens,
        event.cache_write_tokens,
        event.provider_cost_usd,
        event.estimated,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_event_loop(
    supervisor: &mut Supervisor,
    cfg: &Config,
    svarm: bool,
    mut size: Size,
    byte_rx: mpsc::Receiver<Vec<u8>>,
    stdin_rx: mpsc::Receiver<Vec<u8>>,
    action_tx: mpsc::Sender<Action>,
    action_rx: mpsc::Receiver<Action>,
    emitter: Option<&Arc<Emitter>>,
    watch_claude_jsonl: bool,
) -> anyhow::Result<()> {
    let mut redactor = StreamingRedactor::new(
        RedactStyle::for_svarm(svarm),
        cfg.security.redaction.holdback_bytes,
        cfg.security.redaction.enabled,
    );
    let finops = Arc::new(Mutex::new(FinopsEngine::from_config(&cfg.finops)));
    let security_cfg = cfg.security.clone();
    let finops_cfg = cfg.finops.clone();

    let (sec_tx, sec_rx) = mpsc::channel::<Vec<u8>>();
    let (fin_tx, fin_rx) = mpsc::channel::<Vec<u8>>();
    let sec_actions = action_tx.clone();
    let sec_handle = thread::Builder::new()
        .name("falk-security".into())
        .spawn(move || {
            while let Ok(chunk) = sec_rx.recv() {
                let text = String::from_utf8_lossy(&chunk);
                if let Some(action) = action_from_verdict(inspect_chunk(&text, &security_cfg)) {
                    let _ = sec_actions.send(action);
                }
            }
        })
        .ok();

    let fin_actions = action_tx.clone();
    let finops_thread = Arc::clone(&finops);
    let emit_fin = emitter.cloned();
    let run_id = cfg.svarm.run_id.clone();
    let task_id = cfg.svarm.task_id.clone();
    let fin_handle = thread::Builder::new()
        .name("falk-finops".into())
        .spawn(move || {
            while let Ok(chunk) = fin_rx.recv() {
                let text = String::from_utf8_lossy(&chunk);
                let mut engine = finops_thread.lock().expect("finops lock");
                let outcome = engine.ingest_chunk(&text, &finops_cfg);
                if let Some(em) = &emit_fin {
                    for ev in &outcome.events {
                        let _ = em.emit(&usage_ndjson(&run_id, &task_id, ev));
                    }
                }
                for decision in &outcome.decisions {
                    match decision {
                        LimitDecision::SoftWarn { total_usd, limit } => {
                            let _ = fin_actions.send(Action::Warn {
                                message: format!("finops soft limit {total_usd} >= {limit}"),
                            });
                            if let Some(em) = &emit_fin {
                                let _ = em.emit(&Event::Limit {
                                    kind: LimitKind::Soft,
                                    total_usd: *total_usd,
                                    ceiling_usd: Some(*limit),
                                });
                            }
                        }
                        LimitDecision::HardKill { total_usd, limit } => {
                            if let Some(em) = &emit_fin {
                                let _ = em.emit(&Event::Limit {
                                    kind: LimitKind::Hard,
                                    total_usd: *total_usd,
                                    ceiling_usd: Some(*limit),
                                });
                            }
                            let _ = fin_actions.send(Action::Kill {
                                reason: format!("finops hard limit {total_usd} >= {limit}"),
                            });
                        }
                        LimitDecision::Loop { reason, repeats } => {
                            if let Some(em) = &emit_fin {
                                let _ = em.emit(&Event::Loop {
                                    reason: reason.clone(),
                                    repeats: *repeats,
                                });
                            }
                            let _ = fin_actions.send(Action::Kill {
                                reason: reason.clone(),
                            });
                        }
                        LimitDecision::PromptTokens { total, limit }
                        | LimitDecision::CompletionTokens { total, limit } => {
                            let _ = fin_actions.send(Action::Kill {
                                reason: format!("token ceiling {total} >= {limit}"),
                            });
                        }
                    }
                }
            }
        })
        .ok();

    let claude_jsonl = if watch_claude_jsonl {
        Some(spawn_tailer(fin_tx.clone()))
    } else {
        None
    };

    // Signal forwarding (standalone). In Svärm mode SIGWINCH will not arrive
    // from Port.open; we still install handlers so a local --svarm test works.
    let signals = install_signal_pipe();

    let mut stdout = io::stdout();
    let grace = Duration::from_millis(cfg.pty.kill_grace_ms);
    let mut killed = false;

    loop {
        if let Ok(Some(_)) = supervisor.try_wait() {
            // Drain remaining PTY bytes, then leave.
            while let Ok(chunk) = byte_rx.try_recv() {
                emit_hot(&mut redactor, &chunk, &mut stdout, &sec_tx, &fin_tx)?;
            }
            let tail = redactor.flush();
            if !tail.is_empty() {
                stdout.write_all(&tail)?;
                stdout.flush()?;
            }
            break;
        }

        // stdin → PTY
        while let Ok(bytes) = stdin_rx.try_recv() {
            supervisor.writer().write_all(&bytes)?;
            supervisor.writer().flush().ok();
        }

        // hot-path PTY → stdout
        match byte_rx.recv_timeout(Duration::from_millis(20)) {
            Ok(chunk) => emit_hot(&mut redactor, &chunk, &mut stdout, &sec_tx, &fin_tx)?,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                let tail = redactor.flush();
                if !tail.is_empty() {
                    stdout.write_all(&tail)?;
                    stdout.flush()?;
                }
                break;
            }
        }

        while let Ok(action) = action_rx.try_recv() {
            match action {
                Action::Warn { message } => {
                    warn!("{message}");
                    runtime_notice(&format!("falk: {message}"));
                    if let Some(em) = emitter {
                        let _ = em.emit(&Event::Warn {
                            component: "runtime".into(),
                            message,
                        });
                    }
                }
                Action::Block { reason } => {
                    runtime_notice(&format!("falk: blocking: {reason}"));
                    if let Some(em) = emitter {
                        let _ = em.emit(&Event::Security {
                            verdict: "block".into(),
                            reason: reason.clone(),
                        });
                    }
                    let _ = supervisor.signal_group(SignalKind::Int);
                }
                Action::Kill { reason } => {
                    runtime_notice(&format!("falk: killing process tree: {reason}"));
                    if let Some(em) = emitter {
                        let _ = em.emit(&Event::Security {
                            verdict: "kill".into(),
                            reason: reason.clone(),
                        });
                    }
                    if !killed {
                        let _ = supervisor.kill_tree(grace);
                        killed = true;
                    }
                }
            }
        }

        if let Some(ref sig_rx) = signals {
            while let Ok(signum) = sig_rx.try_recv() {
                if let Some(kind) = forwarded_signal_for(signum) {
                    match kind {
                        SignalKind::Winch => {
                            // Port-vs-PTY: in Svärm mode this typically never fires.
                            size = detect_size(size.rows, size.cols);
                            let _ = supervisor.resize(size);
                            let _ = supervisor.signal_group(SignalKind::Winch);
                        }
                        SignalKind::Int | SignalKind::Term => {
                            let _ = supervisor.signal_group(kind);
                        }
                        SignalKind::Kill => {
                            let _ = supervisor.kill_tree(grace);
                            killed = true;
                        }
                    }
                }
            }
        }
    }
    // Disconnect subscribers so they drain remaining chunks and exit.
    // Join them here so incremental Usage.Record NDJSON is flushed before
    // falk returns the child's exit status.
    if let Some((stop, handle)) = claude_jsonl {
        let _ = stop.send(());
        let _ = handle.join();
    }
    drop(sec_tx);
    drop(fin_tx);
    if let Some(handle) = sec_handle {
        let _ = handle.join();
    }
    if let Some(handle) = fin_handle {
        let _ = handle.join();
    }
    Ok(())
}

/// Raw-mode PTYs do not translate LF → CR-LF, so `eprintln!` overlays the
/// child's TUI mid-line. Always start a notice on its own row.
fn runtime_notice(message: &str) {
    let mut err = io::stderr();
    let _ = err.write_all(b"\r\n");
    let _ = err.write_all(message.as_bytes());
    let _ = err.write_all(b"\r\n");
    let _ = err.flush();
}

fn emit_hot(
    redactor: &mut StreamingRedactor,
    chunk: &[u8],
    stdout: &mut io::Stdout,
    sec_tx: &mpsc::Sender<Vec<u8>>,
    fin_tx: &mpsc::Sender<Vec<u8>>,
) -> io::Result<()> {
    let visible = redactor.push(chunk);
    if !visible.is_empty() {
        stdout.write_all(&visible)?;
        stdout.flush()?;
    }
    // Non-blocking subscribers: unbounded mpsc send only fails if the
    // receiver is gone; we never wait on AST or cost math here.
    let _ = sec_tx.send(chunk.to_vec());
    let _ = fin_tx.send(chunk.to_vec());
    Ok(())
}

fn block_parent_signals() {
    #[cfg(unix)]
    {
        use nix::sys::signal::{SigSet, Signal};
        let mut set = SigSet::empty();
        set.add(Signal::SIGINT);
        set.add(Signal::SIGTERM);
        set.add(Signal::SIGWINCH);
        let _ = set.thread_block();
    }
}

fn install_signal_pipe() -> Option<mpsc::Receiver<i32>> {
    #[cfg(unix)]
    {
        let (tx, rx) = mpsc::channel();
        thread::Builder::new()
            .name("falk-signals".into())
            .spawn(move || signal_wait_loop(tx))
            .ok()?;
        Some(rx)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

#[cfg(unix)]
fn signal_wait_loop(tx: mpsc::Sender<i32>) {
    use nix::sys::signal::{SigSet, Signal};
    let mut set = SigSet::empty();
    set.add(Signal::SIGINT);
    set.add(Signal::SIGTERM);
    set.add(Signal::SIGWINCH);
    let _ = set.thread_block();
    loop {
        match set.wait() {
            Ok(sig) => {
                let num = sig as i32;
                if tx.send(num).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use falk_config::FinopsConfig;
    use falk_finops::FinopsEngine;
    use falk_telemetry::Sink;
    use rust_decimal::Decimal;
    use std::str::FromStr;
    use std::time::Instant;

    #[test]
    fn finish_io_threads_does_not_join_blocking_stdin() {
        let (hold_tx, hold_rx) = mpsc::channel::<()>();
        let blocked = thread::spawn(move || {
            let _ = hold_rx.recv();
        });
        let reader = thread::spawn(|| {});
        let start = Instant::now();
        finish_io_threads(reader, Some(blocked));
        assert!(
            start.elapsed() < Duration::from_millis(400),
            "joining a blocked stdin pump would hang past the child's exit"
        );
        drop(hold_tx);
    }

    #[test]
    fn block_verdict_is_not_warn() {
        let warn = action_from_verdict(Verdict::Warn {
            reason: "blocked command `rm`".into(),
        });
        let block = action_from_verdict(Verdict::Block {
            reason: "blocked command `rm`".into(),
        });
        let kill = action_from_verdict(Verdict::Kill {
            reason: "blocked command `rm`".into(),
        });
        assert!(matches!(warn, Some(Action::Warn { .. })), "{warn:?}");
        assert!(
            matches!(block, Some(Action::Block { .. })),
            "Block must not collapse to Warn: {block:?}"
        );
        assert!(matches!(kill, Some(Action::Kill { .. })), "{kill:?}");
        assert!(!matches!(block, Some(Action::Warn { .. })));
    }

    #[test]
    fn ingest_then_usage_ndjson_has_usage_record_fields() {
        let cfg = FinopsConfig::default();
        let mut engine = FinopsEngine::from_config(&cfg);
        let chunk = r#"{"provider":"anthropic","model_id":"claude-sonnet-4","usage":{"input_tokens":12,"output_tokens":34},"provider_cost_usd":"0.042"}"#;
        let outcome = engine.ingest_chunk(chunk, &cfg);
        assert_eq!(outcome.events.len(), 1);
        let emitter = Emitter::new(Sink::Buffer).unwrap();
        let line = emitter
            .emit(&usage_ndjson("run-1", "task-9", &outcome.events[0]))
            .unwrap();
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
        assert!(v.get("status").is_none());
        assert!(v.get("wait_reason").is_none());
        assert!(v.get("pending_question").is_none());
        assert!(v.get("attempts").is_none());
        let _ = Decimal::from_str("0.042").unwrap();
    }
}
