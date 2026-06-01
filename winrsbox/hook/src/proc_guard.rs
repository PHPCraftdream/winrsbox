// Process guard — blocks cross-process code injection, dangerous process spawns,
// parent-PID spoofing, and Job Object breakaway.
//
// Hook 1: NtOpenProcess — denies PROCESS_TERMINATE | CREATE_THREAD | VM_OPERATION |
//         VM_WRITE | DUP_HANDLE | CREATE_PROCESS | SET_QUOTA | SET_INFORMATION |
//         SUSPEND_RESUME on non-owned PIDs. Allows VM_READ, QUERY_INFO (info-leak
//         is out of scope).
// Hook 2: Integrated into hooks.rs hook_nt_create_user_process — blocks denylisted
//         executables (wsl, wmic, LOLBins) and parent-PID spoofing via
//         PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
// Hook 3: NtAssignProcessToJobObject — unconditionally denies Job reassignment
//         from within the sandbox, preventing nested-Job escape on Win10+.
// Hook 4: NtSetInformationProcess — blocks dangerous ProcessInformationClass
//         mutations on foreign (non-owned) processes. Self-process is always
//         allowed for legitimate JIT/runtime usage.
// Hook 5: NtTerminateProcess — untracks child PIDs from process_tracker on
//         exit, preventing unbounded growth and PID-reuse poisoning (P1-2).

use std::sync::OnceLock;

use detour2::GenericDetour;
use ntapi::winapi::shared::ntdef::{HANDLE, NTSTATUS, OBJECT_ATTRIBUTES};
use winapi::ctypes::c_void;
use winapi::um::processthreadsapi::GetCurrentProcessId;
use winapi::shared::ntdef::ULONG;

use crate::anti_rec;
use crate::hooks::{ipc_log, is_trace, STATUS_ACCESS_DENIED};
use crate::process_tracker;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

#[repr(C)]
struct CLIENT_ID {
    UniqueProcess: HANDLE,
    UniqueThread: HANDLE,
}

type FnNtOpenProcess = unsafe extern "system" fn(
    *mut HANDLE,          // ProcessHandle
    u32,                  // DesiredAccess
    *const OBJECT_ATTRIBUTES,
    *const CLIENT_ID,
) -> NTSTATUS;

type FnNtAssignProcessToJobObject = unsafe extern "system" fn(
    *mut c_void,  // JobHandle
    *mut c_void,  // ProcessHandle
) -> NTSTATUS;

type FnNtSetInformationProcess = unsafe extern "system" fn(
    HANDLE,          // ProcessHandle
    ULONG,           // ProcessInformationClass
    *mut c_void,     // ProcessInformation
    ULONG,           // ProcessInformationLength
) -> NTSTATUS;

type FnNtTerminateProcess = unsafe extern "system" fn(
    HANDLE,    // ProcessHandle
    NTSTATUS,  // ExitStatus
) -> NTSTATUS;

// Legacy NtCreateProcess (pre-Vista, but symbol still exported on Win10/11).
// All scalar params widened to usize for detour2 Function trait compat on x64.
//
//   NTSTATUS NtCreateProcess(
//       PHANDLE ProcessHandle,
//       ACCESS_MASK DesiredAccess,
//       POBJECT_ATTRIBUTES ObjectAttributes,
//       HANDLE ParentProcess,
//       BOOLEAN InheritObjectTable,
//       HANDLE SectionHandle,
//       HANDLE DebugPort,
//       HANDLE ExceptionPort
//   );
type FnNtCreateProcess = unsafe extern "system" fn(
    *mut HANDLE,             // ProcessHandle
    usize,                   // DesiredAccess (ACCESS_MASK widened)
    *const OBJECT_ATTRIBUTES,
    HANDLE,                  // ParentProcess
    usize,                   // InheritObjectTable (BOOLEAN widened)
    HANDLE,                  // SectionHandle
    HANDLE,                  // DebugPort
    HANDLE,                  // ExceptionPort
) -> NTSTATUS;

// NtCreateProcessEx — extended variant. Same legacy code-path: section-backed
// process creation that bypasses NtCreateUserProcess. Unconditionally denied.
//
//   NTSTATUS NtCreateProcessEx(
//       PHANDLE ProcessHandle,
//       ACCESS_MASK DesiredAccess,
//       POBJECT_ATTRIBUTES ObjectAttributes,
//       HANDLE ParentProcess,
//       ULONG Flags,
//       HANDLE SectionHandle,
//       HANDLE DebugPort,
//       HANDLE ExceptionPort,
//       BOOLEAN InJob
//   );
type FnNtCreateProcessEx = unsafe extern "system" fn(
    *mut HANDLE,             // ProcessHandle
    usize,                   // DesiredAccess (ACCESS_MASK widened)
    *const OBJECT_ATTRIBUTES,
    HANDLE,                  // ParentProcess
    usize,                   // Flags (ULONG widened)
    HANDLE,                  // SectionHandle
    HANDLE,                  // DebugPort
    HANDLE,                  // ExceptionPort
    usize,                   // InJob (BOOLEAN widened)
) -> NTSTATUS;

// PS_ATTRIBUTE for parent-spoof detection in NtCreateUserProcess attribute list.
#[repr(C)]
struct PS_ATTRIBUTE {
    Attribute: usize,
    Size: usize,
    Value: usize,
    ReturnLength: *mut usize,
}

#[repr(C)]
struct PS_ATTRIBUTE_LIST {
    TotalLength: usize,
    Attributes: [PS_ATTRIBUTE; 1],
}

// ---------------------------------------------------------------------------
// Owned-PID check — delegates to process_tracker (single source of truth).
// Self PID is always allowed; children we spawned are tracked via
// process_tracker::mark_spawned in hooks.rs hook_nt_create_user_process.
// ---------------------------------------------------------------------------

fn pid_owned(pid: u32) -> bool {
    pid == unsafe { GetCurrentProcessId() } || process_tracker::is_owned_child(pid)
}

// ---------------------------------------------------------------------------
// Detour storage
// ---------------------------------------------------------------------------

static HOOK_NT_OPEN_PROCESS: OnceLock<GenericDetour<FnNtOpenProcess>> = OnceLock::new();
static HOOK_NT_ASSIGN_JOB: OnceLock<GenericDetour<FnNtAssignProcessToJobObject>> = OnceLock::new();
static HOOK_NT_SET_INFO_PROCESS: OnceLock<GenericDetour<FnNtSetInformationProcess>> = OnceLock::new();
static HOOK_NT_TERMINATE_PROCESS: OnceLock<GenericDetour<FnNtTerminateProcess>> = OnceLock::new();
static HOOK_NT_CREATE_PROCESS: OnceLock<GenericDetour<FnNtCreateProcess>> = OnceLock::new();
static HOOK_NT_CREATE_PROCESS_EX: OnceLock<GenericDetour<FnNtCreateProcessEx>> = OnceLock::new();

// ---------------------------------------------------------------------------
// NtOpenProcess hook
// ---------------------------------------------------------------------------

const DANGEROUS_ACCESS: u32 =
    0x0001 |  // PROCESS_TERMINATE
    0x0002 |  // PROCESS_CREATE_THREAD
    0x0008 |  // PROCESS_VM_OPERATION
    0x0020 |  // PROCESS_VM_WRITE
    0x0040 |  // PROCESS_DUP_HANDLE
    0x0080 |  // PROCESS_CREATE_PROCESS
    0x0100 |  // PROCESS_SET_QUOTA
    0x0200 |  // PROCESS_SET_INFORMATION
    0x0800 |  // PROCESS_SUSPEND_RESUME
    0x0200_0000 | // MAXIMUM_ALLOWED
    0x1000_0000;  // GENERIC_ALL
// NOT blocked: VM_READ (0x0010), QUERY_INFO (0x0400), QUERY_LIMITED (0x1000)

unsafe extern "system" fn hook_nt_open_process(
    process_handle: *mut HANDLE,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
    client_id: *const CLIENT_ID,
) -> NTSTATUS {
    let call_original = || {
        HOOK_NT_OPEN_PROCESS.get().unwrap().call(
            process_handle, desired_access, object_attributes, client_id,
        )
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if client_id.is_null() {
        return call_original();
    }

    let pid = (*client_id).UniqueProcess as usize as u32;
    let dangerous = desired_access & DANGEROUS_ACCESS;

    if dangerous != 0 && !pid_owned(pid) {
        if is_trace() {
            ipc_log(ipc::LogLevel::Trace,
                format!("proc_open_blocked pid={pid} access=0x{desired_access:08x} dangerous=0x{dangerous:08x}"));
        }
        if !process_handle.is_null() {
            *process_handle = std::ptr::null_mut();
        }
        return STATUS_ACCESS_DENIED;
    }

    call_original()
}

// ---------------------------------------------------------------------------
// NtAssignProcessToJobObject hook — blocks Job reassignment escape
// ---------------------------------------------------------------------------

unsafe extern "system" fn hook_nt_assign_process_to_job_object(
    job: *mut c_void,
    process: *mut c_void,
) -> NTSTATUS {
    let call_original = || {
        HOOK_NT_ASSIGN_JOB.get().unwrap().call(job, process)
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    // Any hooked process is already inside our sandbox Job. An explicit
    // NtAssignProcessToJobObject call from within the sandbox is an escape
    // attempt — the attacker creates an empty Job (no limits) and reassigns
    // themselves into it. On Win10+ nested Jobs allow this, so the process
    // would be in both Jobs but could use the empty one to dodge restrictions.
    // Deny unconditionally.
    if is_trace() {
        ipc_log(ipc::LogLevel::Trace,
            format!("job_assign_blocked job=0x{:x} proc=0x{:x}",
                job as usize, process as usize));
    }
    STATUS_ACCESS_DENIED
}

// ---------------------------------------------------------------------------
// NtSetInformationProcess hook — block dangerous foreign-process mutations
// ---------------------------------------------------------------------------
//
// Classes treated as dangerous on FOREIGN PIDs (self-process is always allowed
// for legitimate JIT/runtime usage):
//   1  ProcessQuotaLimits        — change quotas of another process
//   3  ProcessBasePriority       — set base priority foreign
//   8  ProcessIoPortHandlers     — set IO completion port handlers
//   9  ProcessAccessToken        — assign primary token to foreign process (escape!)
//   20 ProcessPriorityBoost      — boost priority foreign
//   21 ProcessAffinityMask       — change CPU affinity foreign
//   25 ProcessForegroundInformation — set foreground on foreign
//   32 ProcessHandleTracing      — enable handle tracing foreign

const PROCESS_QUOTA_LIMITS: ULONG = 1;
const PROCESS_BASE_PRIORITY: ULONG = 3;
const PROCESS_IO_PORT_HANDLERS: ULONG = 8;
const PROCESS_ACCESS_TOKEN: ULONG = 9;
const PROCESS_PRIORITY_BOOST: ULONG = 20;
const PROCESS_AFFINITY_MASK: ULONG = 21;
const PROCESS_FOREGROUND_INFORMATION: ULONG = 25;
const PROCESS_HANDLE_TRACING: ULONG = 32;

const DANGEROUS_PROC_CLASSES: &[ULONG] = &[
    PROCESS_QUOTA_LIMITS,
    PROCESS_BASE_PRIORITY,
    PROCESS_IO_PORT_HANDLERS,
    PROCESS_ACCESS_TOKEN,
    PROCESS_PRIORITY_BOOST,
    PROCESS_AFFINITY_MASK,
    PROCESS_FOREGROUND_INFORMATION,
    PROCESS_HANDLE_TRACING,
];

unsafe extern "system" fn hook_nt_set_information_process(
    process_handle: HANDLE,
    class: ULONG,
    info: *mut c_void,
    len: ULONG,
) -> NTSTATUS {
    let call_original = || {
        HOOK_NT_SET_INFO_PROCESS.get().unwrap().call(process_handle, class, info, len)
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    if !DANGEROUS_PROC_CLASSES.contains(&class) {
        return call_original();
    }

    // Resolve handle → PID. If self or owned child → allow.
    let target_pid = resolve_process_pid(process_handle);
    if target_pid == 0 || pid_owned(target_pid) {
        return call_original();
    }

    if is_trace() {
        ipc_log(ipc::LogLevel::Trace,
            format!("proc_setinfo_blocked pid={target_pid} class={class}"));
    }
    STATUS_ACCESS_DENIED
}

// ---------------------------------------------------------------------------
// NtTerminateProcess hook — untrack child PIDs on exit (P1-2 fix)
// ---------------------------------------------------------------------------
//
// This is a tracker-cleanup hook, NOT a security hook. Always passes through
// to the original. Prevents unbounded growth of process_tracker and PID-reuse
// poisoning (recycled PID treated as owned child → escape vector).

unsafe extern "system" fn hook_nt_terminate_process(
    process_handle: HANDLE,
    exit_status: NTSTATUS,
) -> NTSTATUS {
    let call_original = || {
        HOOK_NT_TERMINATE_PROCESS.get().unwrap().call(process_handle, exit_status)
    };

    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    // Resolve handle → PID. GetProcessId returns 0 on failure or pseudo-handle
    // for current process (NtCurrentProcess = -1).
    let target_pid = winapi::um::processthreadsapi::GetProcessId(process_handle);
    let self_pid = GetCurrentProcessId();

    // Untrack if it's one of our owned children. Skip self (never tracked)
    // and skip 0 (resolution failure / NtCurrentProcess pseudo-handle).
    if target_pid != 0 && target_pid != self_pid {
        if is_trace() {
            ipc_log(ipc::LogLevel::Trace,
                format!("proc_terminate_untrack pid={target_pid}"));
        }
        process_tracker::untrack(target_pid);
    }

    call_original()
}

// ---------------------------------------------------------------------------
// Legacy NtCreateProcess / NtCreateProcessEx hooks — unconditional deny
// ---------------------------------------------------------------------------
//
// These are rarely-used legacy syscalls retained in ntdll for binary
// compatibility with pre-Vista subsystems. Modern Windows uses
// NtCreateUserProcess; no MS-supplied user-mode code path reaches these.
//
// They are dangerous because they accept a SectionHandle to a mapped image
// and skip the entire RTL_USER_PROCESS_PARAMETERS / PS_ATTRIBUTE_LIST plumbing
// that hooks.rs::hook_nt_create_user_process inspects. A sandboxed child can
// NtCreateSection over an arbitrary EXE, then NtCreateProcessEx(parent=self,
// section=...) — the spawned child has no APC-injected hook.dll, no parent
// validation, no image denylist enforcement. Pure escape.
//
// Mitigation: unconditional STATUS_ACCESS_DENIED. We do not even consult
// pid_owned / image path / section content. Returning early before any pointer
// deref means null/garbage params are safe.

unsafe extern "system" fn hook_nt_create_process(
    _process_handle: *mut HANDLE,
    _desired_access: usize,
    _object_attributes: *const OBJECT_ATTRIBUTES,
    _parent_process: HANDLE,
    _inherit_object_table: usize,
    _section_handle: HANDLE,
    _debug_port: HANDLE,
    _exception_port: HANDLE,
) -> NTSTATUS {
    // Anti-rec guard prevents reentry if our deny-path itself somehow loops
    // back into ntdll (it doesn't, but defense-in-depth keeps invariants).
    let Some(_guard) = anti_rec::enter() else {
        return STATUS_ACCESS_DENIED;
    };

    if is_trace() {
        let _ = crate::hooks::ipc_log_violation(ipc::Req::Log {
            pid: unsafe { GetCurrentProcessId() },
            level: ipc::LogLevel::Warn,
            msg: format!("proc_create_legacy_blocked: NtCreateProcess"),
        });
    }
    STATUS_ACCESS_DENIED
}

unsafe extern "system" fn hook_nt_create_process_ex(
    _process_handle: *mut HANDLE,
    _desired_access: usize,
    _object_attributes: *const OBJECT_ATTRIBUTES,
    _parent_process: HANDLE,
    _flags: usize,
    _section_handle: HANDLE,
    _debug_port: HANDLE,
    _exception_port: HANDLE,
    _in_job: usize,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return STATUS_ACCESS_DENIED;
    };

    if is_trace() {
        let _ = crate::hooks::ipc_log_violation(ipc::Req::Log {
            pid: unsafe { GetCurrentProcessId() },
            level: ipc::LogLevel::Warn,
            msg: format!("proc_create_legacy_blocked: NtCreateProcessEx"),
        });
    }
    STATUS_ACCESS_DENIED
}

// ---------------------------------------------------------------------------
// Resolve process handle → PID via NtQueryInformationProcess
// ---------------------------------------------------------------------------

fn resolve_process_pid(handle: HANDLE) -> u32 {
    #[repr(C)]
    struct PROCESS_BASIC_INFORMATION {
        reserved1: *mut c_void,
        peb_base_address: *mut c_void,
        reserved2: [*mut c_void; 2],
        unique_process_id: usize,
        reserved3: *mut c_void,
    }

    type FnNtQueryInformationProcess = unsafe extern "system" fn(
        HANDLE,
        ULONG,       // ProcessInformationClass (0 = ProcessBasicInformation)
        *mut c_void, // ProcessInformation
        ULONG,       // ProcessInformationLength
        *mut ULONG,  // ReturnLength
    ) -> NTSTATUS;

    static QIP: OnceLock<Option<FnNtQueryInformationProcess>> = OnceLock::new();
    let qip = QIP.get_or_init(|| {
        unsafe {
            let addr = crate::hooks::ntdll_export("NtQueryInformationProcess\0".as_bytes())?;
            Some(std::mem::transmute(addr as usize))
        }
    });

    if let Some(qip_fn) = qip {
        let mut pbi = std::mem::MaybeUninit::<PROCESS_BASIC_INFORMATION>::uninit();
        let status = unsafe {
            qip_fn(
                handle,
                0, // ProcessBasicInformation
                pbi.as_mut_ptr() as *mut c_void,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as ULONG,
                std::ptr::null_mut(),
            )
        };
        if status >= 0 {
            return unsafe { (*pbi.as_ptr()).unique_process_id as u32 };
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Spawn denylist (checked in hooks.rs hook_nt_create_user_process)
// ---------------------------------------------------------------------------

const SPAWN_DENYLIST: &[&str] = &[
    // WSL / Linux subsystem.
    //
    // `bash.exe` intentionally LEFT OUT of the basename-deny set: that
    // basename collides with the perfectly-fine MinGW/Git Bash binary at
    // `C:\Program Files\Git\…\bash.exe`, which AI agents and dev tooling
    // legitimately spawn (claude-code's git-clone path was hitting this
    // and failing with EPERM). The legacy WSL stub at
    // `C:\Windows\System32\bash.exe` is still denied — see
    // `is_path_locked_wsl_bash` below.
    "wsl.exe", "wslhost.exe",
    // WMI cmdline
    "wmic.exe",
    // Classic LOLBins — script/DLL execution from signed binaries
    "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "bitsadmin.exe", "certutil.exe",
    "installutil.exe", "msbuild.exe",
    "regasm.exe", "regsvcs.exe",
    // Delayed-execution / callback persistence LOLBins
    "at.exe",            // deprecated task scheduler — still functional on some configs
    "applaunch.exe",     // .NET LOLBin — launches arbitrary managed DLL
    "mavinject.exe",     // App-V tool — injects DLL into running process
    "forfiles.exe",      // command runner via filter expression
    "pcalua.exe",        // Program Compatibility Assistant — runs anything
    "scriptrunner.exe",  // generic script execution LOLBin
    "cmstp.exe",         // Connection Manager — executes INF directives
];

/// Extract the lowercased basename (final path component) from an image path.
fn basename_of(image_path: &str) -> String {
    let lower = image_path.to_lowercase().replace('/', "\\");
    lower.rsplit('\\').next().unwrap_or(&lower).to_string()
}

/// Pure denylist-matching predicate over the two name signals we trust:
/// the on-disk `basename` (always available) and the PE's `OriginalFilename`
/// from its VERSIONINFO resource (available for signed system binaries).
///
/// Returns true if EITHER name matches the denylist. Matching on
/// OriginalFilename defeats the copy-rename bypass (M3):
/// `copy wsl.exe foo.exe & start foo.exe` — the basename `foo.exe` is not in
/// the list, but the version resource still reports OriginalFilename `wsl.exe`.
///
/// Pure and filesystem-free so it is unit-testable. Both inputs are compared
/// case-insensitively against the (lowercase) denylist entries.
pub fn is_denied_by_names(basename: &str, original: Option<&str>) -> bool {
    let basename_lc = basename.to_lowercase();
    if SPAWN_DENYLIST.iter().any(|entry| basename_lc == *entry) {
        return true;
    }
    if let Some(orig) = original {
        let orig_lc = orig.to_lowercase();
        if SPAWN_DENYLIST.iter().any(|entry| orig_lc == *entry) {
            return true;
        }
    }
    false
}

/// Check if an image path matches the spawn denylist. Returns true if blocked.
///
/// Matches against both the on-disk basename AND the PE's OriginalFilename
/// (read from the VERSIONINFO resource), so a copy-renamed denylisted binary
/// is still caught (M3). OriginalFilename is best-effort: if the version
/// resource is missing or the file is unreadable, only the basename is used.
///
/// Plus the path-locked WSL-bash check (see `is_path_locked_wsl_bash`) so
/// `\System32\bash.exe` still blocks despite the basename leaving the
/// denylist (basename collision with Git Bash).
pub fn is_denylisted(image_path: &str) -> bool {
    let basename = basename_of(image_path);
    let original = original_filename(image_path);
    if is_denied_by_names(&basename, original.as_deref()) {
        return true;
    }
    is_path_locked_wsl_bash(image_path)
}

/// `true` when `image_path` points at the legacy WSL stub
/// (`C:\Windows\System32\bash.exe`) or its store-app twin in
/// `\WindowsApps\…\bash.exe`. Pure over the path string so it's
/// unit-testable without any filesystem access.
///
/// The non-path-locked basename "bash.exe" was removed from
/// `SPAWN_DENYLIST` to stop us false-positive-blocking Git Bash
/// (`C:\Program Files\Git\…\bash.exe`); this predicate keeps WSL coverage.
pub fn is_path_locked_wsl_bash(image_path: &str) -> bool {
    let lower = image_path.to_lowercase().replace('/', "\\");
    if !lower.ends_with("\\bash.exe") {
        return false;
    }
    lower.contains(r"\windows\system32\")
        || lower.contains(r"\windows\sysnative\")
        || lower.contains(r"\windowsapps\")
}

// ---------------------------------------------------------------------------
// PE OriginalFilename extraction (VERSIONINFO resource) — M3
// ---------------------------------------------------------------------------

/// Read the `OriginalFilename` string from a PE file's VERSIONINFO resource.
///
/// Returns `None` if the file has no version resource, is unreadable by the
/// sandbox (GetFileVersionInfoW fails), or the string is absent. Callers fall
/// back to the basename in that case.
///
/// Cost: one cold version-resource read per process spawn. Not cached — the
/// spawn hook is already a slow path.
fn original_filename(image_path: &str) -> Option<String> {
    use winapi::shared::minwindef::{DWORD, LPVOID, UINT, WORD};
    use winapi::um::winver::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};

    // #[repr(C)] translation record from \VarFileInfo\Translation.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct LangAndCodepage {
        language: WORD,
        code_page: WORD,
    }

    if image_path.is_empty() {
        return None;
    }

    // Null-terminated UTF-16 path for the W APIs.
    let path_w: Vec<u16> = image_path.encode_utf16().chain(Some(0)).collect();

    // SAFETY: `path_w` is a valid null-terminated UTF-16 string that outlives
    // the call. `handle` is a stack-owned out-param. Returns 0 on failure
    // (missing resource / unreadable file), which we check.
    let mut handle: DWORD = 0;
    let size = unsafe { GetFileVersionInfoSizeW(path_w.as_ptr(), &mut handle) };
    if size == 0 {
        return None;
    }

    // Backing store for the version block. Sized exactly per the API contract.
    let mut block: Vec<u8> = vec![0u8; size as usize];

    // SAFETY: `path_w` is valid as above; we pass the buffer we just allocated
    // of `size` bytes and the matching `size`. On success it fills `block` with
    // an opaque, self-relative version structure; on failure returns 0.
    let ok = unsafe {
        GetFileVersionInfoW(path_w.as_ptr(), 0, size, block.as_mut_ptr() as *mut _)
    };
    if ok == 0 {
        return None;
    }

    // Resolve the (language, codepage) pair from the translation table.
    let translation_sub: Vec<u16> =
        "\\VarFileInfo\\Translation".encode_utf16().chain(Some(0)).collect();
    let mut trans_ptr: LPVOID = std::ptr::null_mut();
    let mut trans_len: UINT = 0;

    // SAFETY: `block` holds a valid version structure (GetFileVersionInfoW
    // succeeded). `translation_sub` is a valid null-terminated UTF-16 sub-block
    // path. `trans_ptr`/`trans_len` are stack out-params. On success `trans_ptr`
    // points INTO `block` (borrowed, valid while `block` lives) and `trans_len`
    // is the byte length of the translation array. Returns 0 / leaves ptr null
    // if absent.
    let trans_ok = unsafe {
        VerQueryValueW(
            block.as_ptr() as *const _,
            translation_sub.as_ptr(),
            &mut trans_ptr,
            &mut trans_len,
        )
    };

    // Build the list of (lang, codepage) candidates. If there is no translation
    // table, fall back to the common English/Unicode pair (0x0409, 0x04B0).
    let mut candidates: Vec<LangAndCodepage> = Vec::new();
    if trans_ok != 0
        && !trans_ptr.is_null()
        && (trans_len as usize) >= std::mem::size_of::<LangAndCodepage>()
    {
        let count = trans_len as usize / std::mem::size_of::<LangAndCodepage>();
        // SAFETY: `trans_ptr` points to `count` consecutive LangAndCodepage
        // records inside `block` (its length is `trans_len` bytes, and
        // `count * size_of::<LangAndCodepage>() <= trans_len`). The data is
        // valid for reads while `block` is alive (it is, below). The struct is
        // #[repr(C)] with the documented WORD,WORD layout.
        let slice = unsafe {
            std::slice::from_raw_parts(trans_ptr as *const LangAndCodepage, count)
        };
        candidates.extend_from_slice(slice);
    }
    // Always try the conventional default last, in case the per-translation
    // lookups miss (some binaries store strings under a different sub-block
    // than their declared translation).
    candidates.push(LangAndCodepage { language: 0x0409, code_page: 0x04B0 });

    for lc in candidates {
        let sub_block = format!(
            "\\StringFileInfo\\{:04x}{:04x}\\OriginalFilename",
            lc.language, lc.code_page
        );
        let sub_w: Vec<u16> = sub_block.encode_utf16().chain(Some(0)).collect();
        let mut val_ptr: LPVOID = std::ptr::null_mut();
        let mut val_len: UINT = 0;

        // SAFETY: same invariants as the translation query — `block` is a valid
        // version structure, `sub_w` is a valid null-terminated UTF-16 sub-block
        // path, and the out-params are stack-owned. On success `val_ptr` points
        // into `block` at a UTF-16 string of `val_len` characters (per the
        // VerQueryValue contract for string values).
        let val_ok = unsafe {
            VerQueryValueW(
                block.as_ptr() as *const _,
                sub_w.as_ptr(),
                &mut val_ptr,
                &mut val_len,
            )
        };
        if val_ok == 0 || val_ptr.is_null() || val_len == 0 {
            continue;
        }

        // `val_len` is a count of UTF-16 code units INCLUDING the trailing NUL.
        // Drop the terminator if present.
        let mut char_count = val_len as usize;
        // SAFETY: `val_ptr` references `char_count` valid UTF-16 units within
        // `block` (alive here). We bound the slice to exactly the reported
        // length before reading.
        let wide = unsafe {
            std::slice::from_raw_parts(val_ptr as *const u16, char_count)
        };
        if let Some(&last) = wide.last() {
            if last == 0 {
                char_count -= 1;
            }
        }
        let s = String::from_utf16_lossy(&wide[..char_count]);
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    // Keep `block` explicitly alive until all borrowed pointers above are done.
    drop(block);
    None
}

// ---------------------------------------------------------------------------
// Parent-PID spoof detection via PS_ATTRIBUTE_LIST
// ---------------------------------------------------------------------------

/// Check if the attribute list contains PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
///
/// The PS_ATTRIBUTE encoding: `Attribute = (number) | (input ? 0x20000 : 0) | ...`.
/// PsAttributeParentProcess has number 0 in the NT attribute table.
/// In the PS_ATTRIBUTE_LIST passed to NtCreateUserProcess, the encoded value
/// uses 0x00020000 (PsAttributeParentProcess | PS_ATTRIBUTE_INPUT).
/// We match on the lower 16 bits == 0 (PsAttributeParentProcess number).
pub fn attribute_list_contains_parent_process(attr_list: *const c_void) -> bool {
    if attr_list.is_null() {
        return false;
    }
    let list = attr_list as *const PS_ATTRIBUTE_LIST;
    let total = unsafe { (*list).TotalLength };
    if total < std::mem::size_of::<usize>() {
        return false;
    }
    let attr_count = (total - std::mem::size_of::<usize>()) / std::mem::size_of::<PS_ATTRIBUTE>();
    if attr_count == 0 {
        return false;
    }
    let attrs = unsafe { (*list).Attributes.as_ptr() };
    for i in 0..attr_count {
        let attr = unsafe { &*attrs.add(i) };
        // PsAttributeParentProcess number = 0, encoded with input flag = 0x20000.
        // Match lower 16 bits == 0 — this is the attribute number.
        if (attr.Attribute & 0xFFFF) == 0 && attr.Value != 0 {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Handle-list inheritance detection via PS_ATTRIBUTE_LIST
// ---------------------------------------------------------------------------

/// Check if the attribute list contains PROC_THREAD_ATTRIBUTE_HANDLE_LIST.
///
/// PsAttributeHandleList has attribute number 2 in the NT attribute table.
/// The encoded value uses 0x00020002 (number=2 | PS_ATTRIBUTE_INPUT).
/// We match on the lower 16 bits == 2 (PsAttributeHandleList number).
pub fn attribute_list_contains_handle_list(attr_list: *const c_void) -> bool {
    if attr_list.is_null() {
        return false;
    }
    let list = attr_list as *const PS_ATTRIBUTE_LIST;
    let total = unsafe { (*list).TotalLength };
    if total < std::mem::size_of::<usize>() {
        return false;
    }
    let attr_count = (total - std::mem::size_of::<usize>()) / std::mem::size_of::<PS_ATTRIBUTE>();
    if attr_count == 0 {
        return false;
    }
    let attrs = unsafe { (*list).Attributes.as_ptr() };
    for i in 0..attr_count {
        let attr = unsafe { &*attrs.add(i) };
        if (attr.Attribute & 0xFFFF) == 2 {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Extract image path from RTL_USER_PROCESS_PARAMETERS
// ---------------------------------------------------------------------------

/// Extract the image path from process parameters.
/// Reuses the same offset logic as hooks.rs extract_child_exe (offset 0x60 on x64).
pub unsafe fn extract_image_path(params: *const c_void) -> Option<String> {
    if params.is_null() {
        return None;
    }
    // RTL_USER_PROCESS_PARAMETERS layout on x64:
    //   0x60: ImagePathName (UNICODE_STRING)
    let params_ptr = params as *const u8;
    let image_path_offset = 0x60usize;
    let ustr_ptr = params_ptr.add(image_path_offset) as *const ntapi::winapi::shared::ntdef::UNICODE_STRING;
    let ustr = &*ustr_ptr;
    let char_count = (ustr.Length / 2) as usize;
    if char_count == 0 || ustr.Buffer.is_null() {
        return None;
    }
    let name_slice = std::slice::from_raw_parts(ustr.Buffer, char_count);
    Some(String::from_utf16_lossy(name_slice))
}

// ---------------------------------------------------------------------------
// Install / Uninstall
// ---------------------------------------------------------------------------

pub unsafe fn install() -> Result<(), Box<dyn std::error::Error>> {
    let addr = crate::hooks::ntdll_export("NtOpenProcess\0".as_bytes())
        .ok_or("ntdll export not found: NtOpenProcess")?;
    let target: FnNtOpenProcess = std::mem::transmute(addr as usize);
    let hook_ptr: FnNtOpenProcess = hook_nt_open_process;
    let detour = GenericDetour::<FnNtOpenProcess>::new(target, hook_ptr)
        .map_err(|e| format!("detour init NtOpenProcess: {:?}", e))?;
    HOOK_NT_OPEN_PROCESS.set(detour).ok();
    HOOK_NT_OPEN_PROCESS.get()
        .expect("set above")
        .enable()
        .map_err(|e| format!("detour enable NtOpenProcess: {:?}", e))?;

    let addr2 = crate::hooks::ntdll_export("NtAssignProcessToJobObject\0".as_bytes())
        .ok_or("ntdll export not found: NtAssignProcessToJobObject")?;
    let target2: FnNtAssignProcessToJobObject = std::mem::transmute(addr2 as usize);
    let hook_ptr2: FnNtAssignProcessToJobObject = hook_nt_assign_process_to_job_object;
    let detour2 = GenericDetour::<FnNtAssignProcessToJobObject>::new(target2, hook_ptr2)
        .map_err(|e| format!("detour init NtAssignProcessToJobObject: {:?}", e))?;
    HOOK_NT_ASSIGN_JOB.set(detour2).ok();
    HOOK_NT_ASSIGN_JOB.get()
        .expect("set above")
        .enable()
        .map_err(|e| format!("detour enable NtAssignProcessToJobObject: {:?}", e))?;

    // Hook 4: NtSetInformationProcess — block dangerous foreign-process mutations
    let addr3 = crate::hooks::ntdll_export("NtSetInformationProcess\0".as_bytes())
        .ok_or("ntdll export not found: NtSetInformationProcess")?;
    let target3: FnNtSetInformationProcess = std::mem::transmute(addr3 as usize);
    let hook_ptr3: FnNtSetInformationProcess = hook_nt_set_information_process;
    let detour3 = GenericDetour::<FnNtSetInformationProcess>::new(target3, hook_ptr3)
        .map_err(|e| format!("detour init NtSetInformationProcess: {:?}", e))?;
    HOOK_NT_SET_INFO_PROCESS.set(detour3).ok();
    HOOK_NT_SET_INFO_PROCESS.get()
        .expect("set above")
        .enable()
        .map_err(|e| format!("detour enable NtSetInformationProcess: {:?}", e))?;

    // Hook 5: NtTerminateProcess — untrack child PIDs on exit (P1-2 fix)
    let addr4 = crate::hooks::ntdll_export("NtTerminateProcess\0".as_bytes())
        .ok_or("ntdll export not found: NtTerminateProcess")?;
    let target4: FnNtTerminateProcess = std::mem::transmute(addr4 as usize);
    let hook_ptr4: FnNtTerminateProcess = hook_nt_terminate_process;
    let detour4 = GenericDetour::<FnNtTerminateProcess>::new(target4, hook_ptr4)
        .map_err(|e| format!("detour init NtTerminateProcess: {:?}", e))?;
    HOOK_NT_TERMINATE_PROCESS.set(detour4).ok();
    HOOK_NT_TERMINATE_PROCESS.get()
        .expect("set above")
        .enable()
        .map_err(|e| format!("detour enable NtTerminateProcess: {:?}", e))?;

    // Hook 6/7: Legacy NtCreateProcess / NtCreateProcessEx — unconditional deny.
    // Best-effort install: if a particular Windows build does not export one of
    // these (extremely unlikely on Win10/11 but theoretically possible on
    // stripped-down server SKUs), buffer the error and continue. Failing the
    // whole proc_guard install over a legacy hole would be worse than leaving
    // that single rarely-used path unguarded.
    install_nt_create_process_legacy();

    if is_trace() {
        ipc_log(ipc::LogLevel::Trace, "proc_guard_installed".into());
    }
    Ok(())
}

// Install the two legacy hooks. Both are best-effort — symbol resolution
// failures or detour init failures are buffered, never propagated, so the
// main install() path stays robust.
unsafe fn install_nt_create_process_legacy() {
    // NtCreateProcess
    match crate::hooks::ntdll_export("NtCreateProcess\0".as_bytes()) {
        Some(addr) => {
            let target: FnNtCreateProcess = std::mem::transmute(addr as usize);
            let hook_ptr: FnNtCreateProcess = hook_nt_create_process;
            match GenericDetour::<FnNtCreateProcess>::new(target, hook_ptr) {
                Ok(detour) => {
                    let _ = HOOK_NT_CREATE_PROCESS.set(detour);
                    if let Some(h) = HOOK_NT_CREATE_PROCESS.get() {
                        if let Err(e) = h.enable() {
                            crate::hooks::buffer_install_error(
                                format!("detour enable NtCreateProcess: {:?}", e),
                            );
                        }
                    }
                }
                Err(e) => crate::hooks::buffer_install_error(
                    format!("detour init NtCreateProcess: {:?}", e),
                ),
            }
        }
        None => crate::hooks::buffer_install_error(
            "NtCreateProcess not exported".to_string(),
        ),
    }

    // NtCreateProcessEx
    match crate::hooks::ntdll_export("NtCreateProcessEx\0".as_bytes()) {
        Some(addr) => {
            let target: FnNtCreateProcessEx = std::mem::transmute(addr as usize);
            let hook_ptr: FnNtCreateProcessEx = hook_nt_create_process_ex;
            match GenericDetour::<FnNtCreateProcessEx>::new(target, hook_ptr) {
                Ok(detour) => {
                    let _ = HOOK_NT_CREATE_PROCESS_EX.set(detour);
                    if let Some(h) = HOOK_NT_CREATE_PROCESS_EX.get() {
                        if let Err(e) = h.enable() {
                            crate::hooks::buffer_install_error(
                                format!("detour enable NtCreateProcessEx: {:?}", e),
                            );
                        }
                    }
                }
                Err(e) => crate::hooks::buffer_install_error(
                    format!("detour init NtCreateProcessEx: {:?}", e),
                ),
            }
        }
        None => crate::hooks::buffer_install_error(
            "NtCreateProcessEx not exported".to_string(),
        ),
    }
}

pub unsafe fn uninstall() {
    if let Some(h) = HOOK_NT_CREATE_PROCESS_EX.get() {
        let _ = h.disable();
    }
    if let Some(h) = HOOK_NT_CREATE_PROCESS.get() {
        let _ = h.disable();
    }
    if let Some(h) = HOOK_NT_TERMINATE_PROCESS.get() {
        let _ = h.disable();
    }
    if let Some(h) = HOOK_NT_SET_INFO_PROCESS.get() {
        let _ = h.disable();
    }
    if let Some(h) = HOOK_NT_ASSIGN_JOB.get() {
        let _ = h.disable();
    }
    if let Some(h) = HOOK_NT_OPEN_PROCESS.get() {
        let _ = h.disable();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both legacy hooks must return STATUS_ACCESS_DENIED for any input —
    /// including null pointers and zero scalar args — without dereferencing
    /// anything. This is the contract that makes "unconditional deny" safe:
    /// no params are inspected before the early-return.
    #[test]
    fn legacy_process_creation_denied() {
        let expected = STATUS_ACCESS_DENIED;

        let s1 = unsafe {
            hook_nt_create_process(
                std::ptr::null_mut(), // ProcessHandle
                0,                    // DesiredAccess
                std::ptr::null(),     // ObjectAttributes
                std::ptr::null_mut(), // ParentProcess
                0,                    // InheritObjectTable
                std::ptr::null_mut(), // SectionHandle
                std::ptr::null_mut(), // DebugPort
                std::ptr::null_mut(), // ExceptionPort
            )
        };
        assert_eq!(s1, expected, "NtCreateProcess must deny null-arg call");

        let s2 = unsafe {
            hook_nt_create_process_ex(
                std::ptr::null_mut(), // ProcessHandle
                0,                    // DesiredAccess
                std::ptr::null(),     // ObjectAttributes
                std::ptr::null_mut(), // ParentProcess
                0,                    // Flags
                std::ptr::null_mut(), // SectionHandle
                std::ptr::null_mut(), // DebugPort
                std::ptr::null_mut(), // ExceptionPort
                0,                    // InJob
            )
        };
        assert_eq!(s2, expected, "NtCreateProcessEx must deny null-arg call");
    }

    // -----------------------------------------------------------------------
    // PID-reuse poisoning regression (P1-2 / T3)
    // -----------------------------------------------------------------------
    //
    // Hook 5 (NtTerminateProcess → process_tracker::untrack) defends against:
    //   1. our child dies → OS reuses its PID for a foreign process →
    //   2. attacker calls into the foreign PID using PROCESS_VM_OPERATION etc.
    //      → would succeed if `is_owned_child(reused_pid)` still returned true.
    // These tests pin the untrack contract directly (decoupled from the
    // OpenProcess→GetProcessId resolution chain).

    #[test]
    fn pid_reuse_after_terminate_does_not_lie() {
        let fake_pid = 999_999u32;
        // create_time 0 → membership-only: this test pins the untrack contract
        // for a non-live PID, decoupled from the live fingerprint re-query.
        crate::process_tracker::mark_spawned(fake_pid, 1, "fake_child.exe".into(), 0);
        assert!(crate::process_tracker::is_owned_child(fake_pid));

        // Simulate the untrack path the NtTerminateProcess hook would take.
        crate::process_tracker::untrack(fake_pid);
        assert!(
            !crate::process_tracker::is_owned_child(fake_pid),
            "after untrack, the PID must not look owned even if OS reuses it for a foreign process"
        );
    }

    #[test]
    fn untracked_pid_treated_as_foreign() {
        let pid = 999_998u32;
        // PID was never marked → must read as foreign.
        assert!(!crate::process_tracker::is_owned_child(pid));
    }

    // -----------------------------------------------------------------------
    // PS_ATTRIBUTE_LIST edge tests (M-T3)
    // -----------------------------------------------------------------------
    //
    // The functions read `TotalLength` from the first usize of the buffer.
    // The bounds expression `(total - size_of::<usize>()) / size_of::<PS_ATTRIBUTE>()`
    // must not underflow on small `total` values.
    //
    // We can't pass a zero-length buffer (reading `TotalLength` itself would
    // be UB), so for the "tiny total" cases we allocate a buffer at least
    // size_of::<usize>() bytes and ENCODE the total value into the header.
    //
    // For the truly empty case we pass a null pointer (caller contract:
    // null → early return false).

    fn make_attr_buf(total_length: usize) -> Vec<u8> {
        // Always allocate at least one usize so reading TotalLength is sound.
        let mut buf = vec![0u8; std::mem::size_of::<usize>()];
        let bytes = total_length.to_ne_bytes();
        buf[..bytes.len()].copy_from_slice(&bytes);
        buf
    }

    #[test]
    fn attr_list_null_pointer_is_safe() {
        assert!(!attribute_list_contains_parent_process(std::ptr::null()));
        assert!(!attribute_list_contains_handle_list(std::ptr::null()));
    }

    #[test]
    fn attr_list_tiny_total_is_safe() {
        // total = 0 — header claims zero size; must not underflow / index.
        let buf = make_attr_buf(0);
        assert!(!attribute_list_contains_parent_process(buf.as_ptr() as _));
        assert!(!attribute_list_contains_handle_list(buf.as_ptr() as _));
    }

    #[test]
    fn attr_list_total_below_header_is_safe() {
        // total = 4 < size_of::<usize>() (8 on x64) — must not underflow.
        let buf = make_attr_buf(4);
        assert!(!attribute_list_contains_parent_process(buf.as_ptr() as _));
        assert!(!attribute_list_contains_handle_list(buf.as_ptr() as _));
    }

    #[test]
    fn attr_list_only_header_no_attrs() {
        // total = size_of::<usize>() — exactly the header, zero entries.
        // (total - header) / sizeof::<PS_ATTRIBUTE>() must == 0, so the
        // attr_count == 0 short-circuit fires.
        let buf = make_attr_buf(std::mem::size_of::<usize>());
        assert!(!attribute_list_contains_parent_process(buf.as_ptr() as _));
        assert!(!attribute_list_contains_handle_list(buf.as_ptr() as _));
    }

    #[test]
    fn attr_list_parent_with_value_zero_is_not_a_match() {
        // A well-formed PARENT attribute (number=0) but with Value=0 must
        // not be reported as parent-spoof — Value is the PID handle and
        // a null handle is not a spoof.
        let header_size = std::mem::size_of::<usize>();
        let attr_size = std::mem::size_of::<PS_ATTRIBUTE>();
        let total = header_size + attr_size;
        let mut buf = vec![0u8; total];
        // TotalLength
        buf[..header_size].copy_from_slice(&total.to_ne_bytes());
        // PS_ATTRIBUTE { Attribute: 0 (parent), Size: 8, Value: 0, ReturnLength: null }
        // All zero by default — only Size needs setting, and Attribute=0 is parent.
        // Attribute = 0 (number 0 = parent, no INPUT flag — still matches by lower 16 bits).
        // The function checks `(Attribute & 0xFFFF) == 0 && Value != 0`.
        // With Value=0, must return false.
        assert!(!attribute_list_contains_parent_process(buf.as_ptr() as _));
    }

    #[test]
    fn attr_list_with_both_parent_and_handle_list_detects_both() {
        // Two attributes: PARENT (number=0, Value=fake_pid_handle) and
        // HANDLE_LIST (number=2). Both detector functions must report true.
        let header_size = std::mem::size_of::<usize>();
        let attr_size = std::mem::size_of::<PS_ATTRIBUTE>();
        let total = header_size + attr_size * 2;
        let mut buf = vec![0u8; total];
        // TotalLength
        buf[..header_size].copy_from_slice(&total.to_ne_bytes());
        // Build two PS_ATTRIBUTE entries in place.
        let attrs_ptr = unsafe { buf.as_mut_ptr().add(header_size) } as *mut PS_ATTRIBUTE;
        unsafe {
            // [0] PARENT — number=0, Value=non-zero
            (*attrs_ptr.add(0)).Attribute = 0x0002_0000; // PsAttributeParentProcess | INPUT
            (*attrs_ptr.add(0)).Size = std::mem::size_of::<usize>();
            (*attrs_ptr.add(0)).Value = 0xDEAD_BEEF;
            (*attrs_ptr.add(0)).ReturnLength = std::ptr::null_mut();
            // [1] HANDLE_LIST — number=2
            (*attrs_ptr.add(1)).Attribute = 0x0002_0002; // PsAttributeHandleList | INPUT
            (*attrs_ptr.add(1)).Size = std::mem::size_of::<usize>();
            (*attrs_ptr.add(1)).Value = 0xCAFE_BABE;
            (*attrs_ptr.add(1)).ReturnLength = std::ptr::null_mut();
        }
        assert!(attribute_list_contains_parent_process(buf.as_ptr() as _));
        assert!(attribute_list_contains_handle_list(buf.as_ptr() as _));
    }

    // -----------------------------------------------------------------------
    // M3 — content-based denylist (OriginalFilename) classification
    // -----------------------------------------------------------------------

    #[test]
    fn denylist_matches_basename() {
        // Existing behavior preserved: a denylisted basename is blocked,
        // regardless of OriginalFilename.
        assert!(is_denylisted("C:\\Windows\\System32\\wsl.exe"));
        assert!(is_denylisted("c:/windows/system32/WSL.EXE")); // case + slash
        assert!(is_denylisted("rundll32.exe"));
        assert!(!is_denylisted("C:\\Windows\\System32\\notepad.exe"));
    }

    #[test]
    fn denied_by_names_basename_only() {
        // Pure helper: basename hit, no original filename.
        assert!(is_denied_by_names("wsl.exe", None));
        assert!(is_denied_by_names("WSL.EXE", None)); // case-insensitive
        assert!(!is_denied_by_names("foo.exe", None));
        // Original present but also clean → not denied.
        assert!(!is_denied_by_names("foo.exe", Some("notepad.exe")));
    }

    #[test]
    fn denylist_matches_original_filename_when_renamed() {
        // The copy-rename bypass: on-disk name is innocuous, but the PE's
        // OriginalFilename still reports the denylisted name. Must be blocked.
        assert!(is_denied_by_names("foo.exe", Some("wsl.exe")));
        assert!(is_denied_by_names("totally_legit.exe", Some("WSL.EXE")));
        // Neither name denylisted → allowed.
        assert!(!is_denied_by_names("a.exe", Some("b.exe")));
        // `bash.exe` is intentionally NOT in the basename denylist — the
        // path-locked check `is_path_locked_wsl_bash` covers the WSL stub
        // location while leaving Git Bash alone. So a renamed-from-bash.exe
        // is allowed by name; the path check is what catches the WSL case.
        assert!(!is_denied_by_names("a.exe", Some("bash.exe")));
    }

    // -- is_path_locked_wsl_bash ------------------------------------------------
    //
    // Regression coverage for the Git-Bash false-positive: we removed
    // `bash.exe` from the basename denylist (it collided with Git's MinGW
    // bash at `\Program Files\Git\…`), and re-added the legacy WSL stub
    // coverage as a PATH-locked rule. These tests pin both halves of that
    // contract.

    #[test]
    fn wsl_bash_at_system32_is_denied() {
        assert!(is_path_locked_wsl_bash(r"C:\Windows\System32\bash.exe"));
        // Case + slash variants.
        assert!(is_path_locked_wsl_bash(r"c:\windows\system32\BASH.EXE"));
        assert!(is_path_locked_wsl_bash(r"c:/windows/system32/bash.exe"));
    }

    #[test]
    fn wsl_bash_at_sysnative_redirector_is_denied() {
        // 32-bit processes see the 64-bit System32 via `\Sysnative\`.
        // Cover that path so a 32-bit attacker spawn doesn't slip through.
        assert!(is_path_locked_wsl_bash(r"C:\Windows\Sysnative\bash.exe"));
    }

    #[test]
    fn wsl_store_app_bash_is_denied() {
        // Modern WSL ships as an MSIX in `\WindowsApps\…`. The exact
        // package directory varies across builds — the predicate matches
        // any path under WindowsApps.
        assert!(is_path_locked_wsl_bash(
            r"C:\Program Files\WindowsApps\MicrosoftCorporationII.WindowsSubsystemForLinux_2.2.4.0_x64__8wekyb3d8bbwe\bash.exe"
        ));
    }

    #[test]
    fn git_bash_is_allowed() {
        // The whole point of the fix: Git Bash at the default install
        // location must NOT be flagged as WSL.
        assert!(!is_path_locked_wsl_bash(r"C:\Program Files\Git\bin\bash.exe"));
        assert!(!is_path_locked_wsl_bash(r"C:\Program Files\Git\usr\bin\bash.exe"));
        // 32-bit Git, or per-user install in AppData.
        assert!(!is_path_locked_wsl_bash(r"C:\Program Files (x86)\Git\bin\bash.exe"));
        assert!(!is_path_locked_wsl_bash(
            r"C:\Users\alice\AppData\Local\Programs\Git\bin\bash.exe"
        ));
    }

    #[test]
    fn msys_and_cygwin_bash_are_allowed() {
        assert!(!is_path_locked_wsl_bash(r"C:\msys64\usr\bin\bash.exe"));
        assert!(!is_path_locked_wsl_bash(r"C:\cygwin64\bin\bash.exe"));
    }

    #[test]
    fn non_bash_exe_is_not_flagged() {
        // Predicate is for `bash.exe` only; other executables anywhere on
        // the system are out of its scope.
        assert!(!is_path_locked_wsl_bash(r"C:\Windows\System32\notepad.exe"));
        assert!(!is_path_locked_wsl_bash(r"C:\Windows\System32\bashlike.exe"));
        // Bare bash without the .exe extension — kernel never opens the
        // image like this on Windows, but defensively reject.
        assert!(!is_path_locked_wsl_bash(r"C:\Windows\System32\bash"));
    }

    #[test]
    fn is_denylisted_combines_name_and_path_checks() {
        // The umbrella entrypoint MUST catch both:
        // (a) the basename-deny set (e.g. wsl.exe anywhere)
        assert!(is_denylisted(r"C:\Windows\System32\wsl.exe"));
        // (b) the path-locked WSL-bash stub
        assert!(is_denylisted(r"C:\Windows\System32\bash.exe"));
        // …without dragging Git Bash into either.
        assert!(!is_denylisted(r"C:\Program Files\Git\bin\bash.exe"));
        assert!(!is_denylisted(r"C:\Program Files\Git\usr\bin\bash.exe"));
    }

    #[test]
    fn original_filename_of_self_does_not_panic() {
        // Read the running test exe's own version info. A test binary usually
        // has no VERSIONINFO resource, so None is the expected (and acceptable)
        // result — the contract is simply that this must not panic / UB.
        let exe = std::env::current_exe().expect("current_exe");
        let exe_str = exe.to_string_lossy().to_string();
        let result = original_filename(&exe_str);
        // Whatever it returns, a present value must be non-empty.
        if let Some(name) = result {
            assert!(!name.is_empty(), "OriginalFilename, if present, is non-empty");
        }
    }

    #[test]
    fn original_filename_missing_file_is_none() {
        // Unreadable / nonexistent path → graceful None (fall back to basename).
        assert_eq!(
            original_filename("Z:\\no\\such\\path\\definitely-missing-xyz.exe"),
            None
        );
        // Empty path → None, no panic.
        assert_eq!(original_filename(""), None);
    }

    #[test]
    fn original_filename_of_system_binary_when_available() {
        // Best-effort end-to-end: a real signed system binary normally carries
        // an OriginalFilename in its version resource. We do not hard-assert the
        // exact value (it varies across Windows builds / SKUs and the file may
        // be unreadable in some CI sandboxes); we only assert that IF we read a
        // value, it is sane. This documents the live behavior without making the
        // test flaky.
        let candidates = [
            "C:\\Windows\\System32\\notepad.exe",
            "C:\\Windows\\System32\\cmd.exe",
        ];
        for path in candidates {
            if let Some(name) = original_filename(path) {
                assert!(!name.is_empty());
                assert!(
                    name.to_lowercase().ends_with(".exe")
                        || !name.contains('\\'),
                    "OriginalFilename should be a bare file name, got {name:?}"
                );
            }
        }
    }

    // ── M4: MAXIMUM_ALLOWED / GENERIC_ALL mask coverage ─────────────────────

    #[test]
    fn dangerous_access_includes_maximum_allowed() {
        assert_ne!(DANGEROUS_ACCESS & 0x0200_0000, 0, "MAXIMUM_ALLOWED must be in DANGEROUS_ACCESS");
    }

    #[test]
    fn dangerous_access_includes_generic_all() {
        assert_ne!(DANGEROUS_ACCESS & 0x1000_0000, 0, "GENERIC_ALL must be in DANGEROUS_ACCESS");
    }

    #[test]
    fn dangerous_access_still_includes_specific_bits() {
        assert_ne!(DANGEROUS_ACCESS & 0x0002, 0, "PROCESS_CREATE_THREAD");
        assert_ne!(DANGEROUS_ACCESS & 0x0020, 0, "PROCESS_VM_WRITE");
        assert_ne!(DANGEROUS_ACCESS & 0x0040, 0, "PROCESS_DUP_HANDLE");
    }
}
