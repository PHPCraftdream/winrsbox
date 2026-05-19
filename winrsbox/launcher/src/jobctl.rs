// Job Objects — kernel-enforced process group management.
//
// Assigns sandboxed process (and all its descendants) to a Job Object with:
//   - KILL_ON_JOB_CLOSE: launcher dies → kernel kills all children atomically
//   - Optional memory limit per-process
//   - Optional DIE_ON_UNHANDLED_EXCEPTION

/// Configuration for Job Object limits.
#[derive(Debug, Clone)]
pub struct JobLimits {
    pub kill_on_close: bool,
    pub memory_bytes: Option<u64>,
    pub die_on_unhandled: bool,
}

impl Default for JobLimits {
    fn default() -> Self {
        Self {
            kill_on_close: true,
            memory_bytes: None,
            die_on_unhandled: true,
        }
    }
}

impl JobLimits {
    pub fn with_memory(mut self, bytes: Option<u64>) -> Self {
        self.memory_bytes = bytes;
        self
    }

    /// Compute the LimitFlags DWORD from our settings. Pure function.
    pub fn limit_flags(&self) -> u32 {
        let mut flags = 0u32;
        if self.kill_on_close {
            flags |= 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        }
        if self.memory_bytes.is_some() {
            flags |= 0x100; // JOB_OBJECT_LIMIT_PROCESS_MEMORY
        }
        if self.die_on_unhandled {
            flags |= 0x400; // JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        }
        flags
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_kill_on_close() {
        let lim = JobLimits::default();
        assert!(lim.kill_on_close);
        assert_ne!(lim.limit_flags() & 0x2000, 0);
    }

    #[test]
    fn default_has_die_on_unhandled() {
        let lim = JobLimits::default();
        assert_ne!(lim.limit_flags() & 0x400, 0);
    }

    #[test]
    fn no_memory_limit_by_default() {
        let lim = JobLimits::default();
        assert!(lim.memory_bytes.is_none());
        assert_eq!(lim.limit_flags() & 0x100, 0);
    }

    #[test]
    fn with_memory_sets_flag() {
        let lim = JobLimits::default().with_memory(Some(4 * 1024 * 1024 * 1024));
        assert_ne!(lim.limit_flags() & 0x100, 0);
        assert_eq!(lim.memory_bytes, Some(4 * 1024 * 1024 * 1024));
    }

    #[test]
    fn with_memory_none_clears() {
        let lim = JobLimits::default().with_memory(None);
        assert_eq!(lim.limit_flags() & 0x100, 0);
    }

    #[test]
    fn all_flags_combined() {
        let lim = JobLimits {
            kill_on_close: true,
            memory_bytes: Some(1),
            die_on_unhandled: true,
        };
        assert_eq!(lim.limit_flags(), 0x2000 | 0x100 | 0x400);
    }

    #[test]
    fn no_flags_if_all_disabled() {
        let lim = JobLimits {
            kill_on_close: false,
            memory_bytes: None,
            die_on_unhandled: false,
        };
        assert_eq!(lim.limit_flags(), 0);
    }
}
