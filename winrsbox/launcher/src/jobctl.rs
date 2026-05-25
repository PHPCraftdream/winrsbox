// Job Objects — kernel-enforced process group management.
//
// Assigns sandboxed process (and all its descendants) to a Job Object with:
//   - KILL_ON_JOB_CLOSE: launcher dies -> kernel kills all children atomically
//   - Optional memory limit per-process
//   - Optional DIE_ON_UNHANDLED_EXCEPTION
//   - UI restrictions: block foreign window handles, clipboard, desktop access

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

/// UI restriction flags (kernel-enforced via JobObjectBasicUIRestrictions).
#[derive(Debug, Clone, Copy)]
pub struct UiRestrictions {
    pub no_foreign_handles: bool,    // UILIMIT_HANDLES       = 0x01
    pub no_read_clipboard: bool,     // UILIMIT_READCLIPBOARD = 0x02
    pub no_write_clipboard: bool,    // UILIMIT_WRITECLIPBOARD= 0x04
    pub no_system_params: bool,      // UILIMIT_SYSTEMPARAMS  = 0x08
    pub no_display_settings: bool,   // UILIMIT_DISPLAYSETTINGS=0x10
    pub no_global_atoms: bool,       // UILIMIT_GLOBALATOMS   = 0x20
    pub no_desktop: bool,            // UILIMIT_DESKTOP       = 0x40
    pub no_exit_windows: bool,       // UILIMIT_EXITWINDOWS   = 0x80
}

impl Default for UiRestrictions {
    fn default() -> Self {
        Self {
            no_foreign_handles: true,
            no_read_clipboard: true,
            no_write_clipboard: true,
            no_system_params: true,
            no_display_settings: true,
            no_global_atoms: true,
            no_desktop: true,
            no_exit_windows: true,
        }
    }
}

impl UiRestrictions {
    pub fn limit_flags(&self) -> u32 {
        let mut f = 0u32;
        if self.no_foreign_handles    { f |= 0x01; }
        if self.no_read_clipboard     { f |= 0x02; }
        if self.no_write_clipboard    { f |= 0x04; }
        if self.no_system_params      { f |= 0x08; }
        if self.no_display_settings   { f |= 0x10; }
        if self.no_global_atoms       { f |= 0x20; }
        if self.no_desktop            { f |= 0x40; }
        if self.no_exit_windows       { f |= 0x80; }
        f
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

    // -- UiRestrictions tests --

    #[test]
    fn ui_default_all_flags() {
        let ui = UiRestrictions::default();
        assert_eq!(ui.limit_flags(), 0xFF);
    }

    #[test]
    fn ui_individual_flags() {
        assert_eq!(UiRestrictions { no_foreign_handles: true, ..empty_ui() }.limit_flags(), 0x01);
        assert_eq!(UiRestrictions { no_read_clipboard: true, ..empty_ui() }.limit_flags(), 0x02);
        assert_eq!(UiRestrictions { no_write_clipboard: true, ..empty_ui() }.limit_flags(), 0x04);
        assert_eq!(UiRestrictions { no_system_params: true, ..empty_ui() }.limit_flags(), 0x08);
        assert_eq!(UiRestrictions { no_display_settings: true, ..empty_ui() }.limit_flags(), 0x10);
        assert_eq!(UiRestrictions { no_global_atoms: true, ..empty_ui() }.limit_flags(), 0x20);
        assert_eq!(UiRestrictions { no_desktop: true, ..empty_ui() }.limit_flags(), 0x40);
        assert_eq!(UiRestrictions { no_exit_windows: true, ..empty_ui() }.limit_flags(), 0x80);
    }

    #[test]
    fn ui_empty_is_zero() {
        assert_eq!(empty_ui().limit_flags(), 0);
    }

    fn empty_ui() -> UiRestrictions {
        UiRestrictions {
            no_foreign_handles: false,
            no_read_clipboard: false,
            no_write_clipboard: false,
            no_system_params: false,
            no_display_settings: false,
            no_global_atoms: false,
            no_desktop: false,
            no_exit_windows: false,
        }
    }
}
