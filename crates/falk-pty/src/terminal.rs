//! Outer-terminal raw mode + restore-on-drop.
//!
//! Only used in **standalone** mode when stdin is a TTY. Svärm mode keeps the
//! outer stdio cooked so it stays compatible with `Port.open`.

use std::io::{self, IsTerminal};

/// RAII guard: restores the terminal on every path (drop, panic, early return).
pub struct TerminalGuard {
    armed: bool,
}

impl TerminalGuard {
    /// Enter raw mode when `enabled` and stdin is a TTY. Always safe to call.
    pub fn acquire(enabled: bool) -> io::Result<Self> {
        if enabled && io::stdin().is_terminal() {
            crossterm::terminal::enable_raw_mode()?;
            Ok(Self { armed: true })
        } else {
            Ok(Self { armed: false })
        }
    }

    pub fn is_raw(&self) -> bool {
        self.armed
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal(self.armed);
        self.armed = false;
    }
}

/// Restore cooked mode. Idempotent; used from Drop and explicit shutdown.
pub fn restore_terminal(was_raw: bool) {
    if was_raw {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

/// Best-effort current outer terminal size (standalone TTY). Falls back to
/// the configured rows/cols. In Svärm mode the parent is a pipe, so this
/// typically returns the fallback — the Port-vs-PTY resize limitation.
pub fn detect_size(fallback_rows: u16, fallback_cols: u16) -> super::Size {
    match crossterm::terminal::size() {
        Ok((cols, rows)) if rows > 0 && cols > 0 => super::Size { rows, cols },
        _ => super::Size {
            rows: fallback_rows,
            cols: fallback_cols,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_without_tty_is_not_raw() {
        // Tests run with piped stdin; standalone still must not fail.
        let guard = TerminalGuard::acquire(true).expect("acquire");
        assert!(!guard.is_raw());
        drop(guard);
        restore_terminal(false);
    }
}
