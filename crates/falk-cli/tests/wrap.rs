//! Real-binary wrap tests for the skeptic-flagged hang and Usage.Record emit.

use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn falk_bin() -> &'static str {
    env!("CARGO_BIN_EXE_falk")
}

fn wait_exit(child: &mut std::process::Child, budget: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + budget;
    loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => return status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("falk hung longer than {budget:?} (stdin still open)");
            }
            None => thread::sleep(Duration::from_millis(20)),
        }
    }
}

#[test]
fn child_exit_is_delivered_while_parent_keeps_stdin_open() {
    // TTY / Svärm Port.open keep stdin open after the agent exits. falk must
    // still return the child's status instead of joining a blocked stdin.read.
    let mut child = Command::new(falk_bin())
        .args(["--", "/bin/echo", "FALK_PTY_OK"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn falk");
    let _hold_stdin = child.stdin.take();
    let status = wait_exit(&mut child, Duration::from_secs(3));
    let mut out = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut out);
    }
    assert!(status.success(), "status={status:?} out={out:?}");
    assert!(
        out.contains("FALK_PTY_OK"),
        "stdout must contain FALK_PTY_OK, got {out:?}"
    );
}

#[test]
fn svarm_emits_usage_record_ndjson_for_stream_event() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "falk-usage-{}-{}.ndjson",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    let payload = r#"{"provider":"anthropic","model_id":"claude-sonnet-4","usage":{"input_tokens":12,"output_tokens":34},"provider_cost_usd":"0.042"}"#;
    let mut child = Command::new(falk_bin())
        .args([
            "--svarm",
            "--run-id",
            "run-1",
            "--task-id",
            "task-9",
            "--ndjson",
            path.to_str().expect("utf8 path"),
            "--",
            "/bin/echo",
            payload,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn falk --svarm");
    let status = wait_exit(&mut child, Duration::from_secs(5));
    assert!(status.success(), "status={status:?}");
    let body = std::fs::read_to_string(&path).unwrap_or_default();
    let _ = std::fs::remove_file(&path);
    let usage = body.lines().find(|l| l.contains("\"event\":\"usage\""));
    let line = usage.unwrap_or_else(|| panic!("no usage event in NDJSON:\n{body}"));
    let v: serde_json::Value = serde_json::from_str(line).expect("json");
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
}
