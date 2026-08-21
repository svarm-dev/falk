//! Tail Claude Code session JSONL for usage events the TUI never prints.
//!
//! Claude Code writes `~/.claude/projects/<encoded-cwd>/<session>.jsonl`.
//! Each assistant line embeds `message.usage` (Anthropic token fields).
//! Interactive `falk -- claude` has no usage on the PTY, so FinOps must
//! follow these files.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tracing::debug;

const POLL: Duration = Duration::from_millis(250);

/// True when argv0 looks like the Claude Code CLI.
pub fn is_claude_command(argv: &[String]) -> bool {
    argv.first()
        .map(|s| {
            Path::new(s)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(s.as_str())
        })
        .is_some_and(|name| name == "claude" || name == "claude.exe")
}

pub fn jsonl_watch_enabled() -> bool {
    match std::env::var("FALK_CLAUDE_JSONL") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "0" | "false" | "off" | "no")
        }
        Err(_) => true,
    }
}

/// Claude Code encodes the project cwd by replacing path separators with `-`.
/// `/Users/foo/bar` → `-Users-foo-bar`.
pub fn encode_project_path(cwd: &Path) -> String {
    cwd.to_string_lossy().replace('\\', "/").replace('/', "-")
}

pub fn project_dirs(cwd: &Path) -> Vec<PathBuf> {
    let encoded = encode_project_path(cwd);
    claude_roots()
        .into_iter()
        .map(|root| root.join("projects").join(&encoded))
        .collect()
}

fn claude_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(dir) = std::env::var("CLAUDE_CONFIG_DIR") {
        let p = PathBuf::from(dir);
        if !p.as_os_str().is_empty() {
            roots.push(p);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let home = PathBuf::from(home);
        roots.push(home.join(".claude"));
        roots.push(home.join(".config").join("claude"));
    }
    roots
}

struct Cursor {
    offset: u64,
    leftover: Vec<u8>,
}

/// Poll Claude session JSONL files and forward complete lines to `tx`.
/// Files that already existed at start are tailed (history ignored).
/// Files created after start are read from byte 0.
pub fn spawn_tailer(tx: Sender<Vec<u8>>) -> (Sender<()>, JoinHandle<()>) {
    let (stop_tx, stop_rx) = mpsc::channel();
    let handle = thread::Builder::new()
        .name("falk-claude-jsonl".into())
        .spawn(move || {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let dirs = project_dirs(&cwd);
            debug!(?dirs, "watching Claude Code session JSONL");
            let mut cursors: HashMap<PathBuf, Cursor> = HashMap::new();
            for path in list_jsonl(&dirs) {
                let len = fs::metadata(&path).map_or(0, |m| m.len());
                cursors.insert(
                    path,
                    Cursor {
                        offset: len,
                        leftover: Vec::new(),
                    },
                );
            }
            loop {
                match stop_rx.recv_timeout(POLL) {
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                    Err(RecvTimeoutError::Timeout) => {}
                }
                for path in list_jsonl(&dirs) {
                    let cur = cursors.entry(path.clone()).or_insert_with(|| Cursor {
                        offset: 0,
                        leftover: Vec::new(),
                    });
                    match pull_new_lines(&path, cur) {
                        Ok(lines) => {
                            for line in lines {
                                if tx.send(line.into_bytes()).is_err() {
                                    return;
                                }
                            }
                        }
                        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                        Err(err) => debug!(path = %path.display(), %err, "jsonl tail"),
                    }
                }
            }
        })
        .expect("spawn claude jsonl tailer");
    (stop_tx, handle)
}

fn list_jsonl(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for dir in dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("jsonl") {
                out.push(path);
            }
        }
    }
    out
}

fn pull_new_lines(path: &Path, cur: &mut Cursor) -> io::Result<Vec<String>> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    if len < cur.offset {
        cur.offset = 0;
        cur.leftover.clear();
    }
    if len == cur.offset && cur.leftover.is_empty() {
        return Ok(Vec::new());
    }
    file.seek(SeekFrom::Start(cur.offset))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    cur.offset = len;
    if buf.is_empty() {
        return Ok(Vec::new());
    }
    cur.leftover.extend_from_slice(&buf);
    let mut lines = Vec::new();
    while let Some(pos) = cur.leftover.iter().position(|&b| b == b'\n') {
        let raw: Vec<u8> = cur.leftover.drain(..=pos).collect();
        let line = String::from_utf8_lossy(&raw).trim().to_string();
        if !line.is_empty() {
            lines.push(line);
        }
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn encodes_unix_cwd_like_claude_code() {
        assert_eq!(
            encode_project_path(Path::new("/Users/foo/bar")),
            "-Users-foo-bar"
        );
    }

    #[test]
    fn detects_claude_argv() {
        assert!(is_claude_command(&["claude".into()]));
        assert!(is_claude_command(&[
            "/usr/local/bin/claude".into(),
            "-c".into()
        ]));
        assert!(!is_claude_command(&["aider".into()]));
    }

    #[test]
    fn pull_new_lines_skips_then_reads_appends() {
        let dir = std::env::temp_dir().join(format!(
            "falk-jsonl-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("tmpdir");
        let path = dir.join("session.jsonl");
        fs::write(&path, "{\"type\":\"user\"}\n").expect("seed");
        let mut cur = Cursor {
            offset: fs::metadata(&path).unwrap().len(),
            leftover: Vec::new(),
        };
        assert!(pull_new_lines(&path, &mut cur).unwrap().is_empty());
        let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(
            f,
            r#"{{"type":"assistant","message":{{"model":"claude-sonnet-4","usage":{{"input_tokens":9,"output_tokens":3}}}}}}"#
        )
        .unwrap();
        drop(f);
        let lines = pull_new_lines(&path, &mut cur).unwrap();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("input_tokens"));
        let _ = fs::remove_dir_all(&dir);
    }
}
