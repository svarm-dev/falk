//! Signal kinds forwarded from the parent to the child's process group.
//!
//! Standalone: SIGINT / SIGTERM / SIGWINCH are forwarded (SIGWINCH also
//! resizes the inner PTY).
//!
//! Svärm mode: the outer interface is a Svärm `Port.open` pipe, which cannot
//! carry SIGWINCH. Resize is therefore a documented limitation in that mode.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalKind {
    Int,
    Term,
    Kill,
    Winch,
}

impl SignalKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Int => "SIGINT",
            Self::Term => "SIGTERM",
            Self::Kill => "SIGKILL",
            Self::Winch => "SIGWINCH",
        }
    }
}

impl fmt::Display for SignalKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Map a libc signal number to a forwarded kind. Unknown signals are ignored.
pub fn forwarded_signal_for(signum: i32) -> Option<SignalKind> {
    #[cfg(unix)]
    {
        if signum == libc::SIGINT {
            Some(SignalKind::Int)
        } else if signum == libc::SIGTERM {
            Some(SignalKind::Term)
        } else if signum == libc::SIGWINCH {
            Some(SignalKind::Winch)
        } else {
            None
        }
    }
    #[cfg(not(unix))]
    {
        let _ = signum;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_int_term_winch() {
        assert_eq!(forwarded_signal_for(libc::SIGINT), Some(SignalKind::Int));
        assert_eq!(forwarded_signal_for(libc::SIGTERM), Some(SignalKind::Term));
        assert_eq!(
            forwarded_signal_for(libc::SIGWINCH),
            Some(SignalKind::Winch)
        );
        assert_eq!(forwarded_signal_for(0), None);
    }
}
