// Job Objects — kernel-enforced process group management.
//
// Assigns sandboxed process (and all its descendants) to a Job Object with:
//   - KILL_ON_JOB_CLOSE: launcher dies -> kernel kills all children atomically
//   - Optional memory limit per-process
//   - Optional DIE_ON_UNHANDLED_EXCEPTION
//   - UI restrictions: block foreign window handles, clipboard, desktop access
//
// Also owns `FolderJob` (below `JobLimits`/`UiRestrictions`): the RAII
// wrapper around the MP-1 folder-level Job Object
// (`docs/multiprocess-broker-plan.md`) — same "Job Object" concern, just an
// unconfigured, unnamed one used for kernel-truth membership checks
// (`IsProcessInJob`) rather than limit enforcement.

use anyhow::{Context, Result};
use windows::core::{PCWSTR, BOOL};
use windows::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_HANDLE_OPTIONS, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JobObjectBasicAccountingInformation,
    QueryInformationJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
};
use windows::Win32::System::Threading::GetCurrentProcess;

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
    ///
    /// SECURITY: BREAKAWAY_OK (0x0800) and SILENT_BREAKAWAY_OK (0x1000) are
    /// intentionally NEVER set. If either were enabled, a sandboxed child could
    /// escape the Job Object via CreateProcess(CREATE_BREAKAWAY_FROM_JOB) or
    /// silent auto-breakaway — bypassing all kernel-enforced restrictions
    /// (kill-on-close, memory limits, UI restrictions).
    pub fn limit_flags(&self) -> u32 {
        let mut flags = 0u32;
        // JOB_OBJECT_LIMIT_BREAKAWAY_OK       (0x0800) — MUST remain unset
        // JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK (0x1000) — MUST remain unset
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
            // HANDLES off by default: UILIMIT_HANDLES blocks use of HWND
            // handles from processes outside the job, which kills inbound
            // broadcasts like WM_INPUTLANGCHANGE (sent by Explorer/csrss when
            // the user switches keyboard layout). Empirically required for
            // Alt+Shift / Win+Space to work inside the sandbox. The
            // anti-injection role is already covered (and more precisely) by
            // user-mode ui_guard hooks (cross-PID SendInput / PostMessage are
            // denied there). Kernel HANDLES limit is opt-in for hard isolation.
            no_foreign_handles: false,
            no_read_clipboard: false,
            no_write_clipboard: false,
            // SYSTEMPARAMS and DISPLAYSETTINGS off by default — empirically
            // (bisected by serial elimination) they participate in the same
            // class of clipboard-paste breakage as EXITWINDOWS/DESKTOP:
            // any combination of two-or-more of {SYSTEMPARAMS,
            // DISPLAYSETTINGS, EXITWINDOWS} blocks cross-process paste,
            // while all-off restores it. Their documented effects
            // (SystemParametersInfo SET, ChangeDisplaySettings) are mild
            // UX nuisances rather than escape vectors — sandbox-AI doing
            // SPI_SETCURSORS is annoying but recoverable. `--strict-clipboard`
            // does NOT touch these two bits (it sets only READCLIPBOARD |
            // WRITECLIPBOARD, 0x06); the full 8-bit profile is `--strict-ui`
            // (R04-2a), not yet measured for compatibility (R04-2b/2c).
            no_system_params: false,
            no_display_settings: false,
            // GLOBALATOMS off by default: blocking the global atom table breaks
            // Win32 RegisterWindowMessage / WM_INPUTLANGCHANGEREQUEST, which
            // is how Windows broadcasts per-process keyboard-layout switches.
            // Atom table is in-process arrangement (atoms can't escape the
            // sandbox or modify the host).
            no_global_atoms: false,
            // DESKTOP off by default: documented as "prevents SwitchDesktop",
            // but empirically also breaks clipboard PASTE from non-sandboxed
            // apps into the sandboxed wezterm-gui. The clipboard manager
            // lives on the desktop object, and reading data published by a
            // foreign-job source seems to need the same desktop-association
            // privileges this bit revokes. SwitchDesktop itself isn't a
            // meaningful escape vector against the kind of agents we sandbox
            // (interactive sessions where the user is already in front of
            // the screen). `--strict-clipboard` does NOT set this bit (it
            // sets only READCLIPBOARD | WRITECLIPBOARD, 0x06); this bit is
            // only set by the full 8-bit `--strict-ui` profile (R04-2a),
            // not yet measured for compatibility (R04-2b/2c).
            no_desktop: false,
            // EXITWINDOWS off by default — bisected as the empirical
            // blocker for cross-process clipboard PASTE. Docs describe
            // this bit as blocking ExitWindowsEx only, but empirically
            // its set state causes GetClipboardData(CF_UNICODETEXT) to
            // return NULL with ERROR_INVALID_HANDLE on data published
            // by a non-sandboxed source — even though EnumClipboardFormats
            // sees the format. The lost logoff/shutdown protection is
            // re-added at user-mode level by `ui_guard`'s hook on
            // user32!ExitWindowsEx (anti-Win+R-style escape from a
            // sandboxed agent that synthesizes Alt+F4 etc.). `--strict-clipboard`
            // does NOT set this bit (it sets only READCLIPBOARD | WRITECLIPBOARD,
            // 0x06); this bit is only set by the full 8-bit `--strict-ui`
            // profile (R04-2a), not yet measured for compatibility (R04-2b/2c).
            no_exit_windows: false,
        }
    }
}

impl UiRestrictions {
    /// Enable strict clipboard blocking (read + write). Used when
    /// --strict-clipboard CLI flag is set.
    pub fn with_strict_clipboard(mut self) -> Self {
        self.no_read_clipboard = true;
        self.no_write_clipboard = true;
        self
    }

    /// Enable all 8 Job UI restriction bits (`limit_flags() == 0xFF`). Used
    /// when the `--strict-ui` CLI flag is set (R04-2a) — an explicit,
    /// opt-in hardening profile, not a default. This is NOT claimed safe
    /// or compatibility-tested: it may break clipboard, browser OAuth, and
    /// credential-manager workflows that rely on the bits this project's
    /// default deliberately leaves off (see `Default` impl comments above
    /// for the empirical clipboard-paste breakage this was bisected from).
    /// Measuring which of the 4 non-clipboard candidates are safe to enable
    /// individually or in combination is a separate, not-yet-started task
    /// (R04-2b/2c).
    pub fn with_all_restrictions(mut self) -> Self {
        self.no_foreign_handles = true;
        self.no_read_clipboard = true;
        self.no_write_clipboard = true;
        self.no_system_params = true;
        self.no_display_settings = true;
        self.no_global_atoms = true;
        self.no_desktop = true;
        self.no_exit_windows = true;
        self
    }

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

// ─── Folder job (MP-1) ──────────────────────────────────────────────────────

// windows-rs 0.61 doesn't expose JOB_OBJECT_* access-right constants (only
// the limit-flag/UI-restriction types used above); raw bits from the
// documented Job Object access rights, not limit flags.
const JOB_OBJECT_ASSIGN_PROCESS: u32 = 0x0001;
const JOB_OBJECT_QUERY: u32 = 0x0004;

/// Access mask handed to a joining launcher's duplicated folder-job handle:
/// `JOB_OBJECT_QUERY` for `IsProcessInJob` (`JOB_OBJECT_ASSIGN_PROCESS`
/// alone yields `ERROR_ACCESS_DENIED` — confirmed empirically in MP-0 §3),
/// `JOB_OBJECT_ASSIGN_PROCESS` to place its own guest in the folder job.
pub const FOLDER_JOB_CLIENT_ACCESS: u32 = JOB_OBJECT_ASSIGN_PROCESS | JOB_OBJECT_QUERY;

/// RAII owner of the folder's Job Object: no limits, no
/// `KILL_ON_JOB_CLOSE`, no `BREAKAWAY_OK` — literally no
/// `SetInformationJobObject` call at all (breakaway is denied by the OS
/// default when nothing is configured, confirmed in MP-0 §1). Purpose is
/// kernel-enforced "is this process one of ours" via `IsProcessInJob`,
/// never process termination — that's the (nested) session job's role.
pub struct FolderJob {
    handle: HANDLE,
}

impl FolderJob {
    /// Create a new, unnamed folder job with no limits configured.
    pub fn create() -> Result<Self> {
        // SAFETY: no security attributes, no name — a private job object
        //         owned by this process.
        let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .context("CreateJobObjectW(folder job)")?;
        Ok(Self { handle })
    }

    /// The raw handle, valid only in this process.
    pub fn handle(&self) -> HANDLE {
        self.handle
    }

    /// Wrap an ALREADY-open job handle this process now owns exclusively
    /// (e.g. one `Attach` duplicated in) instead of creating a new kernel
    /// job object via [`create`](Self::create). MP-7: a failover winner
    /// reuses the SAME folder job every client already held a working
    /// handle to — job objects are independent kernel objects that outlive
    /// whichever process created them for as long as any handle stays open
    /// (confirmed MP-0 §1/§2), so wrapping, never re-creating, is correct.
    ///
    /// # Safety
    /// `handle` must be a valid, currently-open job-object handle that this
    /// process now owns exclusively — no other code path will close it.
    /// `Drop` closes it exactly once.
    pub unsafe fn from_raw_owned(handle: HANDLE) -> Self {
        Self { handle }
    }

    /// Assign `process` into the folder job (nested alongside whatever job
    /// it may already belong to — folder job -> session job is the
    /// intended two-level nesting, MP-0 §1).
    pub fn assign_process(&self, process: HANDLE) -> Result<()> {
        // SAFETY: self.handle and process are both valid handles (caller's
        //         contract for `process`).
        unsafe { AssignProcessToJobObject(self.handle, process) }
            .context("AssignProcessToJobObject(folder job)")
    }

    /// Kernel-truth membership check. Breakaway is denied by construction,
    /// so membership cannot be faked by anything running inside the job.
    pub fn contains(&self, process: HANDLE) -> Result<bool> {
        let mut result = BOOL(0);
        // SAFETY: self.handle is a valid job handle; process must be a
        //         valid handle (caller's contract); result is a valid
        //         out-pointer.
        unsafe { IsProcessInJob(process, Some(self.handle), &mut result) }
            .context("IsProcessInJob")?;
        Ok(result.as_bool())
    }

    /// MP-8: kernel-truth count of live processes currently in this job
    /// (`JobObjectBasicAccountingInformation.ActiveProcesses`) — used by
    /// `winrsbox broker status` (`Req::BrokerStatus`) to report "processes
    /// in this folder" without a self-reported counter anyone could get out
    /// of sync with reality. Same query `sandbox::child_drain::drain_own_job`
    /// already issues against a (session, not folder) job.
    pub fn active_processes(&self) -> Result<u32> {
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let mut returned = 0u32;
        // SAFETY: self.handle is a valid job handle; info is sized for
        //         JobObjectBasicAccountingInformation; returned is a valid
        //         out-pointer.
        unsafe {
            QueryInformationJobObject(
                Some(self.handle),
                JobObjectBasicAccountingInformation,
                &mut info as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                Some(&mut returned),
            )
        }
        .context("QueryInformationJobObject(folder job, BasicAccounting)")?;
        Ok(info.ActiveProcesses)
    }

    /// Duplicate this job handle into `target_process`'s handle table with
    /// exactly `access` rights (see [`FOLDER_JOB_CLIENT_ACCESS`]). The
    /// returned `HANDLE` value is only meaningful INSIDE `target_process` —
    /// delivering it there is an IPC concern (MP-3), not this function's.
    pub fn duplicate_into(&self, target_process: HANDLE, access: u32) -> Result<HANDLE> {
        let mut dup = HANDLE::default();
        // SAFETY: self.handle is a valid job handle owned by this process;
        //         target_process must be a valid, open process handle
        //         (caller's contract); dup is a valid out-pointer.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                self.handle,
                target_process,
                &mut dup,
                access,
                false,
                DUPLICATE_HANDLE_OPTIONS(0),
            )
        }
        .context("DuplicateHandle(folder job -> target process)")?;
        Ok(dup)
    }
}

/// Assign `process` into the job named by `job` — a free-function twin of
/// [`FolderJob::assign_process`] for a caller that only has a raw handle
/// (MP-6: a client's duplicated `folder_job_handle` from `Attach`, not an
/// owned `FolderJob`). Same underlying call, same MP-0 §1 nesting contract
/// (folder job assigned before the session job).
///
/// # Safety
/// `job` must be a valid, open job-object handle with at least
/// `JOB_OBJECT_ASSIGN_PROCESS` access for the duration of this call;
/// `process` must be a valid, open process handle.
pub unsafe fn assign_process_to_raw_job(job: HANDLE, process: HANDLE) -> Result<()> {
    // SAFETY: forwarded from the caller's contract above.
    unsafe { AssignProcessToJobObject(job, process) }.context("AssignProcessToJobObject(folder job)")
}

impl Drop for FolderJob {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: handle was created by CreateJobObjectW above and is
            //         closed exactly once here.
            unsafe { CloseHandle(self.handle).ok() };
        }
    }
}

// SAFETY: a job object handle has no thread affinity; every operation above
//         is a documented kernel call safe to issue from any thread.
unsafe impl Send for FolderJob {}
unsafe impl Sync for FolderJob {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::process::{Child, Command};
    use windows::Win32::System::Threading::CREATE_NO_WINDOW;

    // ─── FolderJob ───────────────────────────────────────────────────────

    fn spawn_sleeper() -> Child {
        // Real, short-lived child process with a live HANDLE we can assign
        // to a job and probe with IsProcessInJob. No console window.
        Command::new("cmd")
            .args(["/C", "ping -n 3 127.0.0.1 >nul"])
            .creation_flags(CREATE_NO_WINDOW.0)
            .spawn()
            .expect("spawn ping child")
    }

    fn handle_of(child: &Child) -> HANDLE {
        HANDLE(child.as_raw_handle())
    }

    fn kill_and_reap(mut child: Child) {
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn assigned_process_is_contained_unrelated_process_is_not() {
        let job = FolderJob::create().expect("create folder job");
        let member = spawn_sleeper();
        let outsider = spawn_sleeper();

        job.assign_process(handle_of(&member)).expect("assign member");

        assert!(
            job.contains(handle_of(&member)).expect("contains(member)"),
            "assigned process must be reported as contained"
        );
        assert!(
            !job.contains(handle_of(&outsider)).expect("contains(outsider)"),
            "process never assigned to this job must not be reported as contained"
        );

        kill_and_reap(member);
        kill_and_reap(outsider);
    }

    #[test]
    fn active_processes_counts_assigned_members_only() {
        let job = FolderJob::create().expect("create folder job");
        assert_eq!(job.active_processes().expect("active_processes on empty job"), 0);

        let member_a = spawn_sleeper();
        let member_b = spawn_sleeper();
        let outsider = spawn_sleeper();
        job.assign_process(handle_of(&member_a)).expect("assign member_a");
        job.assign_process(handle_of(&member_b)).expect("assign member_b");

        assert_eq!(
            job.active_processes().expect("active_processes with two members"),
            2,
            "count must reflect only processes actually assigned to this job"
        );

        kill_and_reap(member_a);
        kill_and_reap(member_b);
        kill_and_reap(outsider);
    }

    #[test]
    fn duplicated_handle_with_client_access_still_answers_is_process_in_job() {
        let job = FolderJob::create().expect("create folder job");
        let member = spawn_sleeper();
        job.assign_process(handle_of(&member)).expect("assign member");

        // Duplicate into our OWN process (a stand-in for "a launcher
        // process" — the duplicated value is only meaningful in the target
        // process, and using ourselves as the target lets the test use it
        // directly without a second real process).
        let dup = job
            .duplicate_into(unsafe { GetCurrentProcess() }, FOLDER_JOB_CLIENT_ACCESS)
            .expect("duplicate_into(self, CLIENT_ACCESS)");

        let mut result = BOOL(0);
        // SAFETY: dup is the handle just duplicated above with QUERY rights;
        //         member's handle is valid; result is a valid out-pointer.
        unsafe { IsProcessInJob(handle_of(&member), Some(dup), &mut result) }
            .expect("IsProcessInJob via duplicated QUERY handle");
        assert!(result.as_bool());

        // SAFETY: dup was returned by DuplicateHandle above and is closed
        //         exactly once here.
        unsafe { CloseHandle(dup).ok() };
        kill_and_reap(member);
    }

    // ─── JobLimits / UiRestrictions ─────────────────────────────────────

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
    fn ui_default_all_flags_when_strict() {
        let ui = UiRestrictions::default().with_strict_clipboard();
        // Default sets NO bits (all five UI-restriction bits empirically
        // participate in cross-process clipboard breakage — see Default
        // impl). `with_strict_clipboard` adds only READ (0x02) + WRITE
        // (0x04) on top, the two bits that are documented to actually
        // block clipboard access (and the only ones we use for hard
        // hardening).
        assert_eq!(ui.limit_flags(), 0x06);
    }

    #[test]
    fn default_allows_clipboard() {
        let ui = UiRestrictions::default();
        assert!(!ui.no_read_clipboard);
        assert!(!ui.no_write_clipboard);
        assert_eq!(ui.limit_flags() & (0x02 | 0x04), 0);
    }

    #[test]
    fn with_strict_clipboard_sets_both() {
        let ui = UiRestrictions::default().with_strict_clipboard();
        assert!(ui.no_read_clipboard);
        assert!(ui.no_write_clipboard);
        assert_ne!(ui.limit_flags() & 0x02, 0);
        assert_ne!(ui.limit_flags() & 0x04, 0);
    }

    #[test]
    fn ui_default_non_clipboard_flags() {
        let ui = UiRestrictions::default();
        // Default = ZERO. Every kernel UI restriction bit was bisected
        // off because the SYSTEMPARAMS/DISPLAYSETTINGS/EXITWINDOWS/
        // DESKTOP/HANDLES/GLOBALATOMS set, in any pairing, breaks
        // cross-process clipboard paste on Win10 19045. Protection
        // against `ExitWindowsEx` is replaced by a user-mode hook in
        // `ui_guard`. The other bits' documented effects are UX-only
        // (mouse/display settings) and don't warrant the clipboard
        // regression.
        assert_eq!(ui.limit_flags(), 0);
    }

    #[test]
    fn with_all_restrictions_sets_all_eight_bits() {
        let ui = UiRestrictions::default().with_all_restrictions();
        assert!(ui.no_foreign_handles);
        assert!(ui.no_read_clipboard);
        assert!(ui.no_write_clipboard);
        assert!(ui.no_system_params);
        assert!(ui.no_display_settings);
        assert!(ui.no_global_atoms);
        assert!(ui.no_desktop);
        assert!(ui.no_exit_windows);
        assert_eq!(ui.limit_flags(), 0xFF);
    }

    #[test]
    fn default_unaffected_by_with_all_restrictions_regression_pin() {
        // UiRestrictions::default() must stay all-false regardless of the
        // new `with_all_restrictions` builder — this is the regression pin
        // for R04-2a: the default UI-restriction mask never changes.
        let ui = UiRestrictions::default();
        assert_eq!(ui.limit_flags(), 0x00);
    }

    #[test]
    fn with_all_restrictions_is_superset_of_strict_clipboard() {
        // `--strict-ui` (0xFF) must dominate `--strict-clipboard` (0x06)
        // when both are requested together: applying strict-clipboard
        // first and then all_restrictions still yields 0xFF, i.e. the
        // "all restrictions" profile is a strict superset and the
        // composition order doesn't matter.
        let ui = UiRestrictions::default()
            .with_strict_clipboard()
            .with_all_restrictions();
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
    fn job_disallows_breakaway() {
        // SECURITY: if either breakaway flag leaks in, the sandbox is escaped.
        let lim = JobLimits::default();
        let f = lim.limit_flags();
        assert_eq!(f & 0x0800, 0, "JOB_OBJECT_LIMIT_BREAKAWAY_OK must be unset");
        assert_eq!(f & 0x1000, 0, "JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK must be unset");
    }

    #[test]
    fn job_disallows_breakaway_even_with_all_limits() {
        let lim = JobLimits {
            kill_on_close: true,
            memory_bytes: Some(4 * 1024 * 1024 * 1024),
            die_on_unhandled: true,
        };
        let f = lim.limit_flags();
        assert_eq!(f & 0x0800, 0, "JOB_OBJECT_LIMIT_BREAKAWAY_OK must be unset");
        assert_eq!(f & 0x1000, 0, "JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK must be unset");
        assert_ne!(f & 0x2000, 0, "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE must be set");
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
