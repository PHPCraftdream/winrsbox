// ETW behavior scoring — observability layer for suspicious kernel events.
//
// Pure scoring logic: accumulates events per PID, determines terminate threshold.
// The actual ETW subscription (StartTrace/ProcessTrace) is wired separately.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtwEventKind {
    DynamicCodeAllocation,
    SetThreadContext,
    ProcessTrampolined,
    CrossProcessMemoryWrite,
    SuspiciousImageLoad,
    DirectSyscallDetected,
    Other,
}

pub fn score_for_event(kind: EtwEventKind) -> u8 {
    match kind {
        EtwEventKind::DirectSyscallDetected => 15,
        EtwEventKind::DynamicCodeAllocation => 10,
        EtwEventKind::CrossProcessMemoryWrite => 8,
        EtwEventKind::SetThreadContext => 7,
        EtwEventKind::ProcessTrampolined => 6,
        EtwEventKind::SuspiciousImageLoad => 3,
        EtwEventKind::Other => 1,
    }
}

pub const TERMINATE_THRESHOLD: u8 = 25;

pub fn should_terminate(accumulated_score: u8) -> bool {
    accumulated_score >= TERMINATE_THRESHOLD
}

/// Parse a TI provider event_id into our typed kind.
pub fn parse_ti_event_kind(event_id: u16) -> EtwEventKind {
    match event_id {
        11 => EtwEventKind::DynamicCodeAllocation,
        18 => EtwEventKind::SetThreadContext,
        19 => EtwEventKind::ProcessTrampolined,
        _ => EtwEventKind::Other,
    }
}

pub struct EtwScoreboard {
    scores: HashMap<u32, u8>,
}

impl EtwScoreboard {
    pub fn new() -> Self {
        Self { scores: HashMap::new() }
    }

    pub fn record(&mut self, pid: u32, kind: EtwEventKind) -> u8 {
        let entry = self.scores.entry(pid).or_insert(0);
        *entry = entry.saturating_add(score_for_event(kind));
        *entry
    }

    pub fn score(&self, pid: u32) -> u8 {
        self.scores.get(&pid).copied().unwrap_or(0)
    }

    pub fn clear(&mut self, pid: u32) {
        self.scores.remove(&pid);
    }

    pub fn tracked_count(&self) -> usize {
        self.scores.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_direct_syscall_highest() {
        assert!(score_for_event(EtwEventKind::DirectSyscallDetected) >= score_for_event(EtwEventKind::DynamicCodeAllocation));
        assert!(score_for_event(EtwEventKind::DirectSyscallDetected) >= score_for_event(EtwEventKind::SetThreadContext));
    }

    #[test]
    fn score_other_is_lowest_nonzero() {
        assert_eq!(score_for_event(EtwEventKind::Other), 1);
    }

    #[test]
    fn threshold_at_25() {
        assert!(!should_terminate(24));
        assert!(should_terminate(25));
        assert!(should_terminate(255));
    }

    #[test]
    fn scoreboard_accumulates() {
        let mut sb = EtwScoreboard::new();
        let s1 = sb.record(100, EtwEventKind::Other); // +1
        assert_eq!(s1, 1);
        let s2 = sb.record(100, EtwEventKind::SetThreadContext); // +7
        assert_eq!(s2, 8);
        let s3 = sb.record(100, EtwEventKind::DirectSyscallDetected); // +15
        assert_eq!(s3, 23);
    }

    #[test]
    fn scoreboard_saturates() {
        let mut sb = EtwScoreboard::new();
        for _ in 0..20 {
            sb.record(100, EtwEventKind::DirectSyscallDetected); // 20*15=300 > 255
        }
        assert_eq!(sb.score(100), 255);
    }

    #[test]
    fn scoreboard_isolated_per_pid() {
        let mut sb = EtwScoreboard::new();
        sb.record(100, EtwEventKind::DirectSyscallDetected);
        sb.record(200, EtwEventKind::Other);
        assert_eq!(sb.score(100), 15);
        assert_eq!(sb.score(200), 1);
    }

    #[test]
    fn scoreboard_clear_removes() {
        let mut sb = EtwScoreboard::new();
        sb.record(100, EtwEventKind::Other);
        assert_eq!(sb.score(100), 1);
        sb.clear(100);
        assert_eq!(sb.score(100), 0);
    }

    #[test]
    fn scoreboard_unknown_pid_is_zero() {
        let sb = EtwScoreboard::new();
        assert_eq!(sb.score(999), 0);
    }

    #[test]
    fn parse_ti_event_11_is_dynamic_code() {
        assert_eq!(parse_ti_event_kind(11), EtwEventKind::DynamicCodeAllocation);
    }

    #[test]
    fn parse_ti_event_18_is_set_context() {
        assert_eq!(parse_ti_event_kind(18), EtwEventKind::SetThreadContext);
    }

    #[test]
    fn parse_ti_event_unknown_is_other() {
        assert_eq!(parse_ti_event_kind(999), EtwEventKind::Other);
    }

    #[test]
    fn tracked_count() {
        let mut sb = EtwScoreboard::new();
        assert_eq!(sb.tracked_count(), 0);
        sb.record(1, EtwEventKind::Other);
        sb.record(2, EtwEventKind::Other);
        assert_eq!(sb.tracked_count(), 2);
        sb.clear(1);
        assert_eq!(sb.tracked_count(), 1);
    }
}
