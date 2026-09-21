use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemMode {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossProcessOp {
    WriteMemory,
    AllocMemory,
    ProtectMemory,
    CreateThread,
    MapSection,
}

impl CrossProcessOp {
    pub fn name(self) -> &'static str {
        match self {
            Self::WriteMemory => "WriteProcessMemory",
            Self::AllocMemory => "AllocateVirtualMemory",
            Self::ProtectMemory => "ProtectVirtualMemory",
            Self::CreateThread => "CreateRemoteThread",
            Self::MapSection => "MapViewOfSection",
        }
    }
}

pub fn is_self_handle(handle: usize) -> bool {
    handle == usize::MAX || handle == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemPolicy {
    pub cross_process: MemMode,
    pub allow_child_pids: bool,
}

impl Default for MemPolicy {
    fn default() -> Self {
        Self { cross_process: MemMode::Deny, allow_child_pids: true }
    }
}

impl MemPolicy {
    pub fn decide(&self, target_is_self: bool, target_is_child: bool) -> MemMode {
        if target_is_self { return MemMode::Allow; }
        if self.allow_child_pids && target_is_child { return MemMode::Allow; }
        self.cross_process
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_handle_always_allow() {
        assert!(is_self_handle(usize::MAX));
        assert!(!is_self_handle(1234));
    }

    #[test]
    fn op_names() {
        assert_eq!(CrossProcessOp::WriteMemory.name(), "WriteProcessMemory");
        assert_eq!(CrossProcessOp::CreateThread.name(), "CreateRemoteThread");
    }

    #[test]
    fn default_denies_cross_process() {
        let p = MemPolicy::default();
        assert_eq!(p.decide(false, false), MemMode::Deny);
    }

    #[test]
    fn self_always_allowed() {
        let p = MemPolicy { cross_process: MemMode::Deny, allow_child_pids: false };
        assert_eq!(p.decide(true, false), MemMode::Allow);
    }

    #[test]
    fn child_allowed_by_default() {
        let p = MemPolicy::default();
        assert_eq!(p.decide(false, true), MemMode::Allow);
    }

    #[test]
    fn child_denied_when_disabled() {
        let p = MemPolicy { cross_process: MemMode::Deny, allow_child_pids: false };
        assert_eq!(p.decide(false, true), MemMode::Deny);
    }

    #[test]
    fn allow_all_mode() {
        let p = MemPolicy { cross_process: MemMode::Allow, allow_child_pids: false };
        assert_eq!(p.decide(false, false), MemMode::Allow);
    }

    #[test]
    fn cross_process_deny_unknown_pid() {
        let p = MemPolicy::default();
        assert_eq!(p.decide(false, false), MemMode::Deny);
    }
}
