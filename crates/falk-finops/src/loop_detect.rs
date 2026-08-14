//! Sliding-window loop detector on command fingerprints + output hashes +
//! failure markers.

use std::collections::VecDeque;
use std::hash::{Hash, Hasher};

use falk_config::LoopConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopSample {
    pub command_fp: u64,
    pub output_hash: u64,
    pub failed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopTrip {
    pub reason: String,
    pub repeats: usize,
}

#[derive(Debug, Clone)]
pub struct LoopDetector {
    window: VecDeque<LoopSample>,
    window_size: usize,
    repeat_threshold: usize,
    failure_markers: Vec<String>,
    last_command_fp: u64,
}

impl LoopDetector {
    pub fn new(window_size: usize, repeat_threshold: usize, failure_markers: Vec<String>) -> Self {
        Self {
            window: VecDeque::with_capacity(window_size.max(1)),
            window_size: window_size.max(1),
            repeat_threshold: repeat_threshold.max(2),
            failure_markers,
            last_command_fp: 0,
        }
    }

    pub fn from_config(cfg: &LoopConfig) -> Self {
        Self::new(
            cfg.window,
            cfg.repeat_threshold,
            cfg.failure_markers.clone(),
        )
    }

    /// Observe one sample. Returns a trip when the sliding window is filled
    /// with the same fingerprint + hash and failure markers.
    pub fn observe(&mut self, sample: LoopSample) -> Option<LoopTrip> {
        self.window.push_back(sample);
        while self.window.len() > self.window_size {
            self.window.pop_front();
        }
        let repeats = self
            .window
            .iter()
            .filter(|s| {
                s.command_fp == sample.command_fp
                    && s.output_hash == sample.output_hash
                    && s.failed == sample.failed
            })
            .count();
        if sample.command_fp != 0 && sample.failed && repeats >= self.repeat_threshold {
            Some(LoopTrip {
                reason: format!(
                    "repeated command fingerprint {:#x} / output {:#x} with failure markers ({repeats}×)",
                    sample.command_fp, sample.output_hash
                ),
                repeats,
            })
        } else {
            None
        }
    }

    /// Observe a raw stream chunk: hash it, detect failure markers, treat the
    /// previous command fingerprint as the pairing key.
    pub fn observe_chunk(&mut self, chunk: &str) -> Option<LoopTrip> {
        let failed = self
            .failure_markers
            .iter()
            .any(|m| chunk.to_ascii_lowercase().contains(&m.to_ascii_lowercase()));
        let sample = LoopSample {
            command_fp: self.last_command_fp,
            output_hash: hash64(chunk.as_bytes()),
            failed,
        };
        self.observe(sample)
    }

    pub fn note_command(&mut self, command: &str) {
        self.last_command_fp = hash64(command.as_bytes());
    }

    pub fn failure_markers(&self) -> &[String] {
        &self.failure_markers
    }
}

pub fn hash64(bytes: &[u8]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_threshold_repeats() {
        let mut d = LoopDetector::new(8, 3, vec!["error".into()]);
        let s = LoopSample {
            command_fp: 1,
            output_hash: 2,
            failed: true,
        };
        assert!(d.observe(s).is_none());
        assert!(d.observe(s).is_none());
        assert!(d.observe(s).is_some());
    }

    #[test]
    fn chunk_path_uses_failure_markers() {
        let mut d = LoopDetector::new(8, 3, vec!["permission denied".into()]);
        d.note_command("cat /etc/shadow");
        let mut trip = None;
        for _ in 0..3 {
            trip = d.observe_chunk("cat: /etc/shadow: Permission denied\n");
        }
        assert!(trip.is_some());
    }
}
