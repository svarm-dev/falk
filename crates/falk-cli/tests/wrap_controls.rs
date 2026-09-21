//! Real-binary wraps for block/kill/warn, the loop breaker, and token ceilings.
//!
//! Each test spawns the `falk` binary. Children trap SIGINT and SIGTERM before
//! printing, then loop, so only `killpg(SIGKILL)` after the grace period can
//! reap them.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

fn falk_bin() -> &'static str {
    env!("CARGO_BIN_EXE_falk")
}

fn temp_path(ext: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "falk-wrap-{}-{}-{n}.{ext}",
        std::process::id(),
        nanos
    ))
}

fn scrub_falk_env(cmd: &mut Command) {
    for key in [
        "FALK_CONFIG",
        "FALK_CONFIG_PATH",
        "FALK_HARD_LIMIT",
        "FALK_HARD_LIMIT_USD",
        "FALK_SOFT_LIMIT",
        "FALK_SOFT_LIMIT_USD",
        "FALK_SVARM",
        "FALK_MODE",
        "FALK_RUN_ID",
        "FALK_TASK_ID",
        "FALK_TICKET",
        "FALK_ENFORCEMENT",
        "FALK_NDJSON",
        "FALK_NDJSON_PATH",
        "FALK_NDJSON_FD",
        "RUST_LOG",
    ] {
        cmd.env_remove(key);
    }
}

struct Wrap {
    child: std::process::Child,
    reaped: bool,
    ndjson: PathBuf,
    config: PathBuf,
    stdout: Arc<Mutex<String>>,
    stderr: Arc<Mutex<String>>,
    out_thread: Option<thread::JoinHandle<()>>,
    err_thread: Option<thread::JoinHandle<()>>,
}

impl Wrap {
    fn spawn(toml: &str, script: &str) -> Self {
        let config = temp_path("toml");
        let ndjson = temp_path("ndjson");
        std::fs::write(&config, toml).expect("write config");
        let mut cmd = Command::new(falk_bin());
        scrub_falk_env(&mut cmd);
        cmd.args([
            "-c",
            config.to_str().expect("utf8 config"),
            "--svarm",
            "--run-id",
            "run-1",
            "--task-id",
            "task-9",
            "--ndjson",
            ndjson.to_str().expect("utf8 ndjson"),
            "--",
            "/bin/sh",
            "-c",
            script,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn falk");
        let stdout = Arc::new(Mutex::new(String::new()));
        let stderr = Arc::new(Mutex::new(String::new()));
        let out_thread = Some(drain(
            child.stdout.take().expect("stdout"),
            Arc::clone(&stdout),
        ));
        let err_thread = Some(drain(
            child.stderr.take().expect("stderr"),
            Arc::clone(&stderr),
        ));
        Self {
            child,
            reaped: false,
            ndjson,
            config,
            stdout,
            stderr,
            out_thread,
            err_thread,
        }
    }

    fn output(&self) -> String {
        self.stdout.lock().expect("stdout lock").clone()
    }

    fn err(&self) -> String {
        self.stderr.lock().expect("stderr lock").clone()
    }

    fn ndjson(&self) -> String {
        std::fs::read_to_string(&self.ndjson).unwrap_or_default()
    }

    fn wait_budget(&mut self, budget: Duration) -> ExitStatus {
        let deadline = Instant::now() + budget;
        loop {
            match self.child.try_wait().expect("try_wait") {
                Some(status) => {
                    self.reaped = true;
                    return status;
                }
                None if Instant::now() >= deadline => {
                    let stdout = self.output();
                    let stderr = self.err();
                    let body = self.ndjson();
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    self.reaped = true;
                    panic!(
                        "falk still running after {budget:?}\nstdout={stdout:?}\nstderr={stderr:?}\nndjson:\n{body}"
                    );
                }
                None => thread::sleep(Duration::from_millis(20)),
            }
        }
    }

    fn assert_alive(&mut self) {
        match self.child.try_wait().expect("try_wait") {
            None => {}
            Some(status) => {
                self.reaped = true;
                let stdout = self.output();
                let stderr = self.err();
                let body = self.ndjson();
                panic!(
                    "falk exited ({status:?}) but the child should still be running\nstdout={stdout:?}\nstderr={stderr:?}\nndjson:\n{body}"
                );
            }
        }
    }
}

impl Drop for Wrap {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.reaped = true;
        }
        if let Some(handle) = self.out_thread.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.err_thread.take() {
            let _ = handle.join();
        }
        let _ = std::fs::remove_file(&self.ndjson);
        let _ = std::fs::remove_file(&self.config);
    }
}

fn drain(
    mut reader: impl Read + Send + 'static,
    slot: Arc<Mutex<String>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buf = [0u8; 1024];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => slot
                    .lock()
                    .expect("drain lock")
                    .push_str(&String::from_utf8_lossy(&buf[..n])),
            }
        }
    })
}

fn wait_output(wrap: &Wrap, needle: &str, budget: Duration) -> String {
    let deadline = Instant::now() + budget;
    loop {
        let got = wrap.output();
        if got.contains(needle) || Instant::now() >= deadline {
            return got;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn assert_no_task_fields(body: &str) {
    for line in body.lines().filter(|line| !line.is_empty()) {
        let value: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|err| panic!("ndjson line is not json: {err}: {line}"));
        for key in ["status", "wait_reason", "pending_question", "attempts"] {
            assert!(value.get(key).is_none(), "{key} in {line}");
        }
    }
}

fn security_verdicts(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|line| {
            let value: serde_json::Value = serde_json::from_str(line).ok()?;
            if value.get("event").and_then(|v| v.as_str()) == Some("security") {
                value
                    .get("verdict")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            } else {
                None
            }
        })
        .collect()
}

fn security_toml(mode: &str) -> String {
    format!(
        r#"
[pty]
kill_grace_ms = 200

[security]
enforcement = "{mode}"

[security.blocklist]
commands = ["rm"]
"#
    )
}

/// Trap before the detectable line so SIGTERM cannot win the race.
const RM_SCRIPT: &str =
    "trap '' INT TERM; printf '%s\\n' 'rm -rf /tmp/x'; while true; do sleep 30; done";

const LOOP_HITS: &str = r#"trap '' INT TERM; i=0; while [ "$i" -lt 8 ]; do printf '%s\n' 'echo error'; sleep 0.15; i=$((i+1)); done; while true; do sleep 30; done"#;

const LOOP_MISS: &str = r#"trap '' INT TERM; i=0; while [ "$i" -lt 8 ]; do printf '%s\n' '{"note":"error"}'; sleep 0.15; i=$((i+1)); done; while true; do sleep 30; done"#;

fn loop_toml() -> String {
    r#"
[pty]
kill_grace_ms = 200

[finops.loop]
window = 8
repeat_threshold = 4
failure_markers = ["error"]
"#
    .to_string()
}

fn usage_script(json: &str) -> String {
    format!("trap '' INT TERM; printf '%s\\n' '{json}'; while true; do sleep 30; done")
}

fn limit_line<'a>(body: &'a str, kind: &str) -> serde_json::Value {
    body.lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|value| {
            value.get("event").and_then(|v| v.as_str()) == Some("limit")
                && value.get("kind").and_then(|v| v.as_str()) == Some(kind)
        })
        .unwrap_or_else(|| panic!("no limit event kind={kind} in:\n{body}"))
}

#[test]
fn enforcement_block_kills_with_block_verdict() {
    let mut wrap = Wrap::spawn(&security_toml("block"), RM_SCRIPT);
    let status = wrap.wait_budget(Duration::from_secs(8));
    let body = wrap.ndjson();
    println!("block status={status:?}\n{body}");
    assert_eq!(
        security_verdicts(&body),
        vec!["block".to_string()],
        "{body}"
    );
    let line = body
        .lines()
        .find(|line| line.contains("\"verdict\":\"block\""))
        .unwrap_or_else(|| panic!("missing block verdict:\n{body}"));
    let value: serde_json::Value = serde_json::from_str(line).unwrap();
    let reason = value["reason"].as_str().unwrap_or("");
    assert!(
        reason.contains("blocklist"),
        "reason should name the blocklist: {reason}"
    );
    assert_no_task_fields(&body);
}

#[test]
fn enforcement_kill_kills_with_kill_verdict() {
    let mut wrap = Wrap::spawn(&security_toml("kill"), RM_SCRIPT);
    let status = wrap.wait_budget(Duration::from_secs(8));
    let body = wrap.ndjson();
    println!("kill status={status:?}\n{body}");
    assert_eq!(security_verdicts(&body), vec!["kill".to_string()], "{body}");
    assert_no_task_fields(&body);
}

#[test]
fn enforcement_warn_leaves_the_child_running() {
    let mut wrap = Wrap::spawn(&security_toml("warn"), RM_SCRIPT);
    let stdout = wait_output(&wrap, "rm -rf /tmp/x", Duration::from_secs(3));
    assert!(
        stdout.contains("rm -rf /tmp/x"),
        "stdout never showed the rm line: {stdout:?} stderr={}",
        wrap.err()
    );
    // Longer than kill_grace_ms (200). A process-group kill would have exited.
    thread::sleep(Duration::from_millis(1200));
    wrap.assert_alive();
    let body = wrap.ndjson();
    println!("warn still running\nstdout={stdout}\n{body}");
    let verdicts = security_verdicts(&body);
    assert!(
        verdicts.iter().all(|v| v != "block" && v != "kill"),
        "warn must not emit a stopping verdict: {verdicts:?}\n{body}"
    );
    assert_no_task_fields(&body);
}

#[test]
fn loop_breaker_kills_on_repeated_command() {
    let mut wrap = Wrap::spawn(&loop_toml(), LOOP_HITS);
    let status = wrap.wait_budget(Duration::from_secs(10));
    let body = wrap.ndjson();
    println!("loop status={status:?}\n{body}");
    let value = body
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|value| value.get("event").and_then(|v| v.as_str()) == Some("loop"))
        .unwrap_or_else(|| panic!("no loop event\nstdout={}\n{body}", wrap.output()));
    let repeats = value["repeats"].as_u64().unwrap_or(0);
    assert!(repeats >= 4, "repeats={repeats} event={value}");
    assert_no_task_fields(&body);
}

#[test]
fn loop_breaker_ignores_failure_marker_without_command() {
    let mut wrap = Wrap::spawn(&loop_toml(), LOOP_MISS);
    let deadline = Instant::now() + Duration::from_secs(6);
    let stdout = loop {
        let got = wrap.output();
        if got.matches("error").count() >= 4 || Instant::now() >= deadline {
            break got;
        }
        thread::sleep(Duration::from_millis(20));
    };
    assert!(
        stdout.matches("error").count() >= 4,
        "failure marker was not repeated\nstdout={stdout:?}\nstderr={}",
        wrap.err()
    );
    thread::sleep(Duration::from_millis(1200));
    wrap.assert_alive();
    let body = wrap.ndjson();
    println!("no-loop still running\n{body}");
    assert!(
        !body.lines().any(|line| line.contains("\"event\":\"loop\"")),
        "loop event without an extracted command:\n{body}"
    );
    assert_no_task_fields(&body);
}

#[test]
fn prompt_token_ceiling_emits_limit_and_kills() {
    let toml = r#"
[pty]
kill_grace_ms = 200

[finops]
max_prompt_tokens = 100
max_completion_tokens = 0
estimator = false
"#;
    let json = r#"{"provider":"anthropic","model_id":"claude-sonnet-4","usage":{"input_tokens":120,"output_tokens":1},"provider_cost_usd":"0.001"}"#;
    assert_token_kill(toml, json, "prompt_tokens", 120, 100);
}

#[test]
fn completion_token_ceiling_emits_limit_and_kills() {
    let toml = r#"
[pty]
kill_grace_ms = 200

[finops]
max_prompt_tokens = 0
max_completion_tokens = 50
estimator = false
"#;
    let json = r#"{"provider":"anthropic","model_id":"claude-sonnet-4","usage":{"input_tokens":1,"output_tokens":80},"provider_cost_usd":"0.001"}"#;
    assert_token_kill(toml, json, "completion_tokens", 80, 50);
}

fn assert_token_kill(toml: &str, json: &str, kind: &str, total: u64, ceiling: u64) {
    let mut wrap = Wrap::spawn(toml, &usage_script(json));
    let status = wrap.wait_budget(Duration::from_secs(8));
    let body = wrap.ndjson();
    println!("{kind} status={status:?}\n{body}");
    let value = limit_line(&body, kind);
    assert_eq!(value["total_tokens"], total, "{value}");
    assert_eq!(value["ceiling_tokens"], ceiling, "{value}");
    assert!(value.get("total_usd").is_none(), "{value}");
    assert!(value.get("ceiling_usd").is_none(), "{value}");
    assert_no_task_fields(&body);
}

#[test]
fn usd_hard_limit_emits_hard_and_kills() {
    let toml = r#"
[pty]
kill_grace_ms = 200

[finops]
hard_limit_usd = "1.00"
max_prompt_tokens = 0
max_completion_tokens = 0
estimator = false
"#;
    let json = r#"{"provider":"anthropic","model_id":"claude-sonnet-4","usage":{"input_tokens":1,"output_tokens":1},"provider_cost_usd":"2.50"}"#;
    let mut wrap = Wrap::spawn(toml, &usage_script(json));
    let status = wrap.wait_budget(Duration::from_secs(8));
    let body = wrap.ndjson();
    println!("hard status={status:?}\n{body}");
    let value = limit_line(&body, "hard");
    assert_eq!(value["total_usd"], "2.50", "{value}");
    assert_eq!(value["ceiling_usd"], "1.00", "{value}");
    assert_no_task_fields(&body);
}

#[test]
fn usd_soft_limit_emits_soft_and_does_not_kill() {
    let toml = r#"
[pty]
kill_grace_ms = 200

[finops]
soft_limit_usd = "0.10"
max_prompt_tokens = 0
max_completion_tokens = 0
estimator = false
"#;
    let json = r#"{"provider":"anthropic","model_id":"claude-sonnet-4","usage":{"input_tokens":1,"output_tokens":1},"provider_cost_usd":"0.50"}"#;
    let mut wrap = Wrap::spawn(toml, &usage_script(json));
    let deadline = Instant::now() + Duration::from_secs(4);
    let body = loop {
        let got = wrap.ndjson();
        if got.contains("\"kind\":\"soft\"") || Instant::now() >= deadline {
            break got;
        }
        thread::sleep(Duration::from_millis(20));
    };
    thread::sleep(Duration::from_millis(1200));
    wrap.assert_alive();
    println!("soft still running\n{body}");
    let value = limit_line(&body, "soft");
    assert_eq!(value["total_usd"], "0.50", "{value}");
    assert_eq!(value["ceiling_usd"], "0.10", "{value}");
    assert_no_task_fields(&body);
}
