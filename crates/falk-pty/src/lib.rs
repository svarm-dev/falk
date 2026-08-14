//! PTY supervisor: spawn the target as session + process-group leader,
//! forward signals / resize, and own the only `killpg` path.
//!
//! Standalone mode: when the outer stdin is a TTY, enter raw mode so the
//! wrapped agent feels identical to running it directly.
//!
//! Svärm mode: the outer interface stays plain stdio (`Port.open` compatible).
//! The inner agent still gets a real PTY. Svärm `Port.open` cannot carry
//! SIGWINCH — resize in Svärm mode is a documented limitation, not a failure.

use std::io::{self, Read, Write};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use portable_pty::{Child, CommandBuilder, MasterPty, NativePtySystem, PtySize, PtySystem};
use tracing::{debug, warn};

pub mod signals;
pub mod terminal;

pub use signals::{SignalKind, forwarded_signal_for};
pub use terminal::{TerminalGuard, restore_terminal};

#[derive(Debug, thiserror::Error)]
pub enum PtyError {
    #[error("failed to open PTY: {0}")]
    Open(String),
    #[error("failed to spawn {command}: {detail}")]
    Spawn { command: String, detail: String },
    #[error("child has no process id")]
    MissingPid,
    #[error("killpg({pgid}, {signal}) failed: {detail}")]
    Killpg {
        pgid: i32,
        signal: &'static str,
        detail: String,
    },
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Other(String),
}

/// Size of the inner PTY.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
    pub rows: u16,
    pub cols: u16,
}

impl Size {
    pub fn new(rows: u16, cols: u16) -> Self {
        Self { rows, cols }
    }

    pub fn fallback() -> Self {
        Self { rows: 24, cols: 80 }
    }

    pub fn to_pty(self) -> PtySize {
        PtySize {
            rows: self.rows,
            cols: self.cols,
            pixel_width: 0,
            pixel_height: 0,
        }
    }
}

/// PID / SID / PGID of the wrapped child.
///
/// After a successful spawn the target is session + process-group leader, so
/// `sid == pgid == pid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessIds {
    pub pid: i32,
    pub sid: i32,
    pub pgid: i32,
}

impl ProcessIds {
    pub fn is_session_and_pgroup_leader(self) -> bool {
        self.pid == self.sid && self.sid == self.pgid
    }
}

/// Result of [`Supervisor::kill_tree`] — the only killpg caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KillReport {
    pub pgid: i32,
    pub term_sent: bool,
    pub kill_sent: bool,
}

/// Owns the child and its process group. All mid-run hard actions go through
/// [`Supervisor::kill_tree`] (`killpg(SIGTERM)` → grace → `killpg(SIGKILL)`).
pub struct Supervisor {
    child: Box<dyn Child + Send + Sync>,
    master: Box<dyn MasterPty + Send>,
    pid: i32,
    pgid: i32,
    writer: Box<dyn Write + Send>,
}

impl Supervisor {
    /// Open a PTY and spawn `argv[0]` with `argv[1..]` as session + PG leader.
    pub fn spawn(argv: &[String], size: Size) -> Result<Self, PtyError> {
        if argv.is_empty() {
            return Err(PtyError::Spawn {
                command: "<empty>".into(),
                detail: "no command".into(),
            });
        }
        let system = NativePtySystem::default();
        let pair = system
            .openpty(size.to_pty())
            .map_err(|err| PtyError::Open(err.to_string()))?;

        let mut cmd = CommandBuilder::new(&argv[0]);
        for arg in &argv[1..] {
            cmd.arg(arg);
        }
        if let Ok(cwd) = std::env::current_dir() {
            cmd.cwd(cwd);
        }

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|err| PtyError::Spawn {
                command: argv.join(" "),
                detail: err.to_string(),
            })?;

        let pid = child.process_id().ok_or(PtyError::MissingPid)? as i32;
        let pgid = wait_for_pgroup_leader(pid)?;

        let writer = pair
            .master
            .take_writer()
            .map_err(|err| PtyError::Other(err.to_string()))?;

        Ok(Self {
            child,
            master: pair.master,
            pid,
            pgid,
            writer,
        })
    }

    pub fn pid(&self) -> i32 {
        self.pid
    }

    pub fn pgid(&self) -> i32 {
        self.pgid
    }

    /// Read SID/PGID/PID via `getsid` / `getpgid` of the live child.
    pub fn process_ids(&self) -> Result<ProcessIds, PtyError> {
        query_process_ids(self.pid)
    }

    pub fn try_clone_reader(&self) -> Result<Box<dyn Read + Send>, PtyError> {
        self.master
            .try_clone_reader()
            .map_err(|err| PtyError::Other(err.to_string()))
    }

    pub fn writer(&mut self) -> &mut dyn Write {
        &mut *self.writer
    }

    pub fn resize(&self, size: Size) -> Result<(), PtyError> {
        self.master
            .resize(size.to_pty())
            .map_err(|err| PtyError::Other(err.to_string()))
    }

    pub fn try_wait(&mut self) -> Result<Option<ChildExit>, PtyError> {
        match self.child.try_wait() {
            Ok(Some(status)) => Ok(Some(ChildExit::from_portable(&status))),
            Ok(None) => Ok(None),
            Err(err) => Err(PtyError::Other(err.to_string())),
        }
    }

    pub fn wait(&mut self) -> Result<ChildExit, PtyError> {
        let status = self
            .child
            .wait()
            .map_err(|err| PtyError::Other(err.to_string()))?;
        Ok(ChildExit::from_portable(&status))
    }

    /// Deliver `sig` to the child's process group (not a kill-tree).
    /// Used for SIGINT / SIGTERM forwarding so the agent sees the same signal.
    pub fn signal_group(&self, kind: SignalKind) -> Result<(), PtyError> {
        send_killpg(self.pgid, kind)
    }

    /// Hard action: `killpg(SIGTERM)` → wait `grace` → `killpg(SIGKILL)` if needed.
    ///
    /// This is the mid-run FinOps / security kill path. Svärm Budget is
    /// preflight-only; this is the gap falk closes. This function is the only
    /// killpg caller for hard termination.
    pub fn kill_tree(&mut self, grace: Duration) -> Result<KillReport, PtyError> {
        let pgid = self.pgid;
        send_killpg(pgid, SignalKind::Term)?;
        let died = wait_dead(&mut *self.child, grace);
        let mut kill_sent = false;
        if !died {
            send_killpg(pgid, SignalKind::Kill)?;
            kill_sent = true;
            let _ = wait_dead(&mut *self.child, Duration::from_secs(2));
        }
        Ok(KillReport {
            pgid,
            term_sent: true,
            kill_sent,
        })
    }
}

/// Drain PTY master output until EOF. Used by tests and the runtime reader.
pub fn read_until_eof(reader: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Normalized child exit. Preserves the raw status for `std::process::exit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildExit {
    pub code: i32,
    pub success: bool,
}

impl ChildExit {
    pub fn from_portable(status: &portable_pty::ExitStatus) -> Self {
        let code = match status.signal() {
            Some(name) => unix_signal_exit_code(name),
            None => status.exit_code() as i32,
        };
        Self {
            code,
            success: status.success(),
        }
    }

    pub fn as_exit_code(self) -> ExitCode {
        ExitCode::from(self.code.clamp(0, 255) as u8)
    }
}

/// Map a `portable-pty` signal name onto the conventional `128 + n` exit code.
pub fn unix_signal_exit_code(name: &str) -> i32 {
    let n = signal_number(name).unwrap_or(1);
    128 + n
}

fn signal_number(name: &str) -> Option<i32> {
    let trimmed = name.trim();
    if let Some(rest) = trimmed.strip_prefix("Signal ") {
        return rest.parse().ok();
    }
    let key = trimmed
        .strip_prefix("SIG")
        .unwrap_or(trimmed)
        .to_ascii_uppercase();
    let n = match key.as_str() {
        "HUP" | "HANGUP" => 1,
        "INT" | "INTERRUPT" => 2,
        "QUIT" => 3,
        "ILL" | "ILLEGAL INSTRUCTION" => 4,
        "TRAP" | "TRACE/BREAKPOINT TRAP" => 5,
        "ABRT" | "ABORTED" | "IOT" => 6,
        "BUS" | "BUS ERROR" => 7,
        "FPE" | "FLOATING POINT EXCEPTION" => 8,
        "KILL" | "KILLED" => 9,
        "USR1" | "USER DEFINED SIGNAL 1" => 10,
        "SEGV" | "SEGMENTATION FAULT" => 11,
        "USR2" | "USER DEFINED SIGNAL 2" => 12,
        "PIPE" | "BROKEN PIPE" => 13,
        "ALRM" | "ALARM CLOCK" => 14,
        "TERM" | "TERMINATED" => 15,
        _ => return None,
    };
    Some(n)
}

/// Send a signal to an entire process group. Exported so tests drive the
/// shipped killpg wrapper; production hard-kills go through [`Supervisor::kill_tree`].
pub fn send_killpg(pgid: i32, kind: SignalKind) -> Result<(), PtyError> {
    #[cfg(unix)]
    {
        use nix::sys::signal::{self, Signal};
        use nix::unistd::Pid;
        let sig = match kind {
            SignalKind::Int => Signal::SIGINT,
            SignalKind::Term => Signal::SIGTERM,
            SignalKind::Kill => Signal::SIGKILL,
            SignalKind::Winch => Signal::SIGWINCH,
        };
        match signal::killpg(Pid::from_raw(pgid), sig) {
            Ok(()) => Ok(()),
            Err(nix::errno::Errno::ESRCH) => {
                debug!(pgid, %kind, "killpg: process group already gone");
                Ok(())
            }
            Err(err) => Err(PtyError::Killpg {
                pgid,
                signal: kind.name(),
                detail: err.to_string(),
            }),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (pgid, kind);
        Err(PtyError::Other(
            "killpg is not available on this platform".into(),
        ))
    }
}

fn wait_dead(child: &mut dyn Child, grace: Duration) -> bool {
    let deadline = Instant::now() + grace;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) => {
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(err) => {
                warn!(error = %err, "try_wait during kill grace failed");
                return false;
            }
        }
    }
}

fn query_process_ids(pid: i32) -> Result<ProcessIds, PtyError> {
    #[cfg(unix)]
    {
        use nix::unistd::{self, Pid};
        let child = Pid::from_raw(pid);
        let sid = unistd::getsid(Some(child))
            .map_err(|err| PtyError::Other(format!("getsid({pid}) failed: {err}")))?;
        let pgid = unistd::getpgid(Some(child))
            .map_err(|err| PtyError::Other(format!("getpgid({pid}) failed: {err}")))?;
        Ok(ProcessIds {
            pid,
            sid: sid.as_raw(),
            pgid: pgid.as_raw(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(ProcessIds {
            pid,
            sid: pid,
            pgid: pid,
        })
    }
}

fn wait_for_pgroup_leader(pid: i32) -> Result<i32, PtyError> {
    // setsid happens in the child between fork and exec; retry briefly.
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut last = query_process_ids(pid)?;
    while Instant::now() < deadline {
        if last.is_session_and_pgroup_leader() {
            return Ok(last.pgid);
        }
        std::thread::sleep(Duration::from_millis(5));
        last = query_process_ids(pid)?;
    }
    // Still use the observed PGID so killpg can target the group.
    if last.pgid != 0 {
        Ok(last.pgid)
    } else {
        Ok(pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn spawn_ok(argv: &[&str]) -> Supervisor {
        let args: Vec<String> = argv.iter().map(|s| (*s).to_string()).collect();
        Supervisor::spawn(&args, Size::fallback()).unwrap_or_else(|err| {
            panic!("PTY spawn failed (environment must provide /dev/ptmx): {err}");
        })
    }

    fn drain(sup: &Supervisor) -> String {
        let mut reader = sup.try_clone_reader().expect("clone reader");
        let bytes = read_until_eof(&mut reader).unwrap_or_default();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[test]
    fn wrap_echo_stdout_contains_token() {
        let mut sup = spawn_ok(&["/bin/echo", "FALK_PTY_OK"]);
        let out = drain(&sup);
        let status = sup.wait().expect("wait");
        assert!(status.success, "{status:?} out={out:?}");
        assert!(
            out.contains("FALK_PTY_OK"),
            "child stdout must contain FALK_PTY_OK, got {out:?}"
        );
    }

    #[test]
    fn wrap_exit_status_preserved() {
        let mut sup = spawn_ok(&["/bin/sh", "-c", "exit 42"]);
        let _ = drain(&sup);
        let status = sup.wait().expect("wait");
        assert_eq!(status.code, 42, "exit status must be preserved");
        assert!(!status.success);
    }

    #[test]
    fn sigkill_child_reports_137() {
        assert_eq!(unix_signal_exit_code("Killed"), 137);
        assert_eq!(unix_signal_exit_code("SIGKILL"), 137);
        assert_eq!(unix_signal_exit_code("SIGINT"), 130);
        let mut sup = spawn_ok(&["/bin/sh", "-c", "kill -s KILL $$"]);
        let _ = drain(&sup);
        let status = sup.wait().expect("wait after self-kill");
        assert!(!status.success);
        assert_eq!(
            status.code, 137,
            "SIGKILL must be 128+9, not portable-pty's 1: {status:?}"
        );
    }

    #[test]
    fn child_is_session_and_process_group_leader() {
        let mut sup = spawn_ok(&[
            "/bin/sh",
            "-c",
            "echo PID=$$; echo SID=$(cut -d' ' -f6 /proc/$$/stat 2>/dev/null || echo x); sleep 0.2",
        ]);
        let ids = sup.process_ids().expect("process_ids");
        assert!(
            ids.is_session_and_pgroup_leader(),
            "expected SID == PGID == PID, got {ids:?}"
        );
        let _ = drain(&sup);
        let _ = sup.wait();
    }

    fn wait_for_ready(sup: &Supervisor) {
        let mut reader = sup.try_clone_reader().expect("clone reader");
        let mut buf = [0u8; 64];
        let mut got = String::new();
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    got.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if got.contains("READY") {
                        return;
                    }
                }
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        panic!("child never printed READY, got {got:?}");
    }

    #[test]
    fn kill_tree_term_then_kill_against_sleep_that_ignores_term() {
        let mut sup = spawn_ok(&[
            "/bin/sh",
            "-c",
            "trap '' TERM; printf 'READY\\n'; while true; do sleep 1; done",
        ]);
        wait_for_ready(&sup);
        let report = sup
            .kill_tree(Duration::from_millis(250))
            .expect("kill_tree");
        assert!(report.term_sent);
        assert!(
            report.kill_sent,
            "child ignored SIGTERM so SIGKILL must be sent: {report:?}"
        );
        let status = sup.wait().expect("wait after kill");
        assert!(!status.success);
        assert_eq!(report.pgid, sup.pgid());
    }

    #[test]
    fn kill_tree_term_alone_when_child_exits() {
        let mut sup = spawn_ok(&["/bin/sh", "-c", "sleep 30"]);
        let report = sup
            .kill_tree(Duration::from_millis(800))
            .expect("kill_tree");
        assert!(report.term_sent);
        let _ = sup.wait();
    }
}
