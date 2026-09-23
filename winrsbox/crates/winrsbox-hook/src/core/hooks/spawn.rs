// NtCreateUserProcess detour: spawn gating, guard-env pinning, overlay image-path redirect, child syscall scan.

use super::*;

// ---------------------------------------------------------------------------
// NtCreateUserProcess type alias + OnceLock (stays here; install_hooks uses it)
// ---------------------------------------------------------------------------

pub(super) type FnNtCreateUserProcess = unsafe extern "system" fn(
    *mut HANDLE,            // ProcessHandle
    *mut HANDLE,            // ThreadHandle
    ACCESS_MASK,            // ProcessDesiredAccess
    ACCESS_MASK,            // ThreadDesiredAccess
    *mut OBJECT_ATTRIBUTES, // ProcessObjectAttributes
    *mut OBJECT_ATTRIBUTES, // ThreadObjectAttributes
    u32,                    // ProcessFlags
    u32,                    // ThreadFlags
    *mut c_void,            // ProcessParameters
    *mut c_void,            // CreateInfo
    *mut c_void,            // AttributeList
) -> NTSTATUS;

pub(super) static HOOK_NT_CREATE_USER_PROCESS: OnceLock<GenericDetour<FnNtCreateUserProcess>> =
    OnceLock::new();

// ---------------------------------------------------------------------------
// Extract child exe from RTL_USER_PROCESS_PARAMETERS
// ---------------------------------------------------------------------------

/// Maximum number of UTF-16 code units in a Windows path. NT object names
/// (incl. UNC + \\?\ paths) cap at 32768 chars. Anything longer is malformed
/// or hostile (kernel returned garbage from a wrong offset).
const MAX_PATH_CHARS: usize = 32768;

/// Extract the executable path from RTL_USER_PROCESS_PARAMETERS.
/// Returns empty string if extraction fails.
//
// SAFETY:
// - `params` must point to a kernel-allocated `RTL_USER_PROCESS_PARAMETERS`
//   structure as populated by `NtCreateUserProcess` /
//   `RtlCreateProcessParametersEx`.
// - The struct layout is undocumented but stable on Windows 10/11 x64:
//   `ImagePathName` (UNICODE_STRING) lives at offset 0x60 (verified
//   empirically; matches the layout reported by reactos/wine and confirmed
//   against ntdll!_RTL_USER_PROCESS_PARAMETERS in WinDbg).
// - The struct's total size is always >= 0x500 in practice (the standard
//   layout is ~0x4F0 + variable-length env block), so reading the 16-byte
//   `UNICODE_STRING` header at offset 0x60 is safe even without explicit
//   length validation.
// - The `UNICODE_STRING.Buffer` pointer is kernel-allocated and valid for
//   the lifetime of the process-params structure (i.e., across this call).
// - If `params.is_null()` we early-return without dereferencing.
//
// Validity guards:
// - We bound the `.Length` field to MAX_PATH_CHARS (32768 UTF-16 units)
//   before slicing.
// - We treat `.Buffer == null` or `.Length == 0` as "no image path",
//   returning an empty string.
//
// Failure mode: if Microsoft ever shifts the offset (e.g., Windows 12),
// we'll read garbage and return a non-existent path — the comparison
// against the launcher's `allowed_image` list / denylist will fail
// closed (deny).
pub(super) unsafe fn extract_child_exe(params: *mut c_void) -> String {
    if params.is_null() {
        return String::new();
    }
    // RTL_USER_PROCESS_PARAMETERS layout on x64 Windows 10/11:
    //   0x60: ImagePathName (UNICODE_STRING — 0x10 bytes)
    let params_ptr = params as *const u8;
    let image_path_offset = 0x60usize;
    let ustr_ptr = params_ptr.add(image_path_offset) as *const UNICODE_STRING;
    let ustr = &*ustr_ptr;
    if ustr.Buffer.is_null() || ustr.Length == 0 {
        return String::new();
    }
    let char_count = (ustr.Length / 2) as usize;
    // Sanity bound: a real ImagePathName never approaches 32K UTF-16 chars.
    // If we read garbage from a shifted offset, this catches the obviously
    // bogus case and fails closed.
    if char_count > MAX_PATH_CHARS {
        return String::new();
    }
    let name_slice = std::slice::from_raw_parts(ustr.Buffer, char_count);
    policy::path::nt_to_dos_lower(name_slice).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// NtCreateUserProcess hook
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// P1-01: direct-syscall pre-execution scan for spawned children
//
// The launcher scans only the ROOT target (launcher/src/main.rs
// `pre_launch_scan`), so the direct-syscall bypass surface (baked-in
// `syscall` instructions, SysWhispers/Hell's Gate class) stayed open for
// every process spawned below the root. This is the in-hook equivalent:
// scan the child's mapped image before it can run, with the same
// terminate-on-failure mode the launcher uses.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Guard configuration snapshot + spawn gate (audit 2026-09-19 High)
// ---------------------------------------------------------------------------

/// Guard-relevant inputs captured ONCE at install time (DllMain), before any
/// guest code has run.
///
/// SINGLE SOURCE OF TRUTH (review XA 2026-09-20, S02): security config is
/// delivered ONLY through the trusted session section
/// (trusted_boot::resolve_effective_config), which the environment can never
/// override — the old env-first / section-second order let a guest-authored
/// FS_SANDBOX_* variable win forever (`OnceLock::set` cannot overwrite), so
/// the env values are now never consulted at all. The snapshot therefore
/// shrank to the two inputs that are NOT config:
///   * decision code reads ONLY the install-time snapshots (GUARD_ENV,
///     DISABLED_HOOK_CATS, trusted_boot::TRUSTED_GUARD) and never the
///     environment, and
///   * `hook_nt_create_user_process` DENIES ON PRESENCE any spawn whose
///     inherited environment carries a security-config variable at all
///     (guard/allow_rwx/disable_hooks/pipe/dll/cwd/root) — since the section
///     is the only legitimate source, an inherited copy has no honest
///     explanation; section and no_track keep their compare-to-snapshot
///     semantics below.
pub(crate) struct GuardEnvSnapshot {
    /// `FS_SANDBOX_SECTION` — the per-session random shared-section name.
    /// Guard-relevant because the section carries `pipe_name` and `dll_path`:
    /// a child booted with a forged name would read attacker-authored config
    /// from an attacker-created section. Empty string = this process itself
    /// booted without a name (then ANY inherited value is a forgery).
    pub(crate) section: String,
    /// `FS_SANDBOX_NO_TRACK` — makes `process_tracker::mark_spawned` skip the
    /// child (the env read lives in the spawn hook now; the tracker itself
    /// never consults the environment). Kept in the snapshot and the gate:
    /// a guard-relevant variable left outside the gate is exactly the drift
    /// the gate exists to prevent.
    ///
    /// Its worst case is milder than the others — an untracked child makes the
    /// injector's own cross-process writes look foreign to memory_guard, so
    /// injection fails and the child is terminated before resume, i.e. a guest
    /// self-DoS rather than an escape. Gated anyway: "fails closed" is not a
    /// reason to leave a knob reachable from the guest.
    pub(crate) no_track: bool,
}

pub(super) static GUARD_ENV: OnceLock<GuardEnvSnapshot> = OnceLock::new();

/// Hook categories parsed once from the trusted section's `disable_hooks`
/// list, consulted only through [`hook_category_disabled`] — the environment
/// is never re-read after install.
pub(super) static DISABLED_HOOK_CATS: OnceLock<Vec<String>> = OnceLock::new();

/// Install-time category gate. Reads only the install-time snapshot.
pub(crate) fn hook_category_disabled(cat: &str) -> bool {
    DISABLED_HOOK_CATS
        .get()
        .map(|cats| cats.iter().any(|d| d == cat))
        .unwrap_or(false)
}

/// Children are scanned under exactly the guard levels the launcher scans the
/// root target: `full` and `static` (launcher/src/main.rs:648). Never under
/// `scan` or `none`. The guard level is the typed `ipc::GuardLevel` from the
/// trusted section — the old case-sensitive string compare silently diverged
/// from the gate's case-insensitive one ("FULL" passed the gate, then failed
/// here; review XA 2026-09-20, S02 #2).
pub(super) fn child_scan_enabled(guard: ipc::GuardLevel) -> bool {
    matches!(guard, ipc::GuardLevel::Full | ipc::GuardLevel::Static)
}

/// Upper bound on the environment walk (UTF-16 chars). A legitimate block
/// stays far below this; a block that runs past it is treated as malformed.
const MAX_GUARD_ENV_CHARS: usize = 1 << 20;

/// Compare the guard-relevant variables observed in a child's would-be
/// environment against the trusted install-time snapshot. `Some(reason)` =
/// mismatch = the spawn must be denied.
///
/// DENY-ON-PRESENCE contract (review XA 2026-09-20, S02): the trusted
/// session section is the ONLY source of security config, so an inherited
/// security-config variable has no legitimate explanation — presence alone
/// is the forgery, whatever the value:
///   * fs_sandbox_guard | fs_sandbox_allow_rwx | fs_sandbox_disable_hooks |
///     fs_sandbox_pipe | fs_sandbox_dll | fs_sandbox_cwd | fs_sandbox_root
///     → denied on ANY presence (the old compare-to-snapshot semantics are
///     gone together with the env config source: even the "trusted value
///     re-stated" case is refused, and absence is still allowed);
///   * fs_sandbox_section — must equal the snapshot's section
///     (case-insensitive); an empty trusted section (this process booted
///     without a name) denies any inherited value;
///   * fs_sandbox_no_track — denied unless the snapshot carries it;
///   * everything else (PATH, fs_sandbox_trace, fs_sandbox_init_event, …)
///     is not guard-relevant here and is ignored.
pub(super) fn guard_env_mismatch(observed: &[(String, String)], trusted: &GuardEnvSnapshot) -> Option<String> {
    for (name, value) in observed {
        match name.to_ascii_lowercase().as_str() {
            // Security config: presence alone is the forgery. The section is
            // the only delivery channel, so the child must not inherit ANY
            // of these — a value that happens to match our own config is
            // still an inherited config channel we cannot vouch for.
            "fs_sandbox_guard"
            | "fs_sandbox_allow_rwx"
            | "fs_sandbox_disable_hooks"
            | "fs_sandbox_pipe"
            | "fs_sandbox_dll"
            | "fs_sandbox_cwd"
            | "fs_sandbox_root" => {
                return Some(format!(
                    "{} must not be inherited: security config is delivered only through the trusted session section",
                    name.to_ascii_uppercase()
                ));
            }
            "fs_sandbox_no_track" => {
                if !trusted.no_track {
                    return Some(format!(
                        "FS_SANDBOX_NO_TRACK forged: child would inherit {value:?}, trusted off"
                    ));
                }
            }
            "fs_sandbox_section" => {
                if !value.eq_ignore_ascii_case(&trusted.section) {
                    return Some(format!(
                        "FS_SANDBOX_SECTION forged: child would inherit {value:?}, trusted {:?}",
                        trusted.section
                    ));
                }
            }
            _ => {}
        }
    }
    None
}

/// Full spawn-time gate: walk the environment the child would inherit and
/// deny the spawn BEFORE the child exists if it carries a guard-relevant
/// variable (see [`guard_env_mismatch`] for the per-variable contract).
///
/// The snapshot is captured in install_hooks before any hook is enabled, so
/// it is always present by the time this hook can run; without it (unit-test
/// context) there is nothing to vouch for and nothing is denied.
pub(super) fn child_guard_env_violation(params: *mut c_void) -> Option<String> {
    let trusted = GUARD_ENV.get()?;
    if params.is_null() {
        // No parameters -> the child inherits no environment at all -> its
        // hook boots with fail-safe defaults.
        return None;
    }
    let observed = match unsafe { read_guard_env_entries(params) } {
        None => return None,
        Some(Ok(entries)) => entries,
        // A block we cannot read is a block we cannot vouch for — fail closed.
        Some(Err(reason)) => return Some(reason.to_string()),
    };
    guard_env_mismatch(&observed, trusted)
}

/// Read the guard-relevant entries from
/// `RTL_USER_PROCESS_PARAMETERS.Environment` (x64 offset 0x80, following the
/// same fixed-offset convention as the 0x60 ImagePathName reads in
/// `extract_child_exe`). The parameters live in OUR address space — the
/// caller (CreateProcessW or raw ntdll use) built them in-process, and the
/// kernel copies the block into the child during the syscall.
///
/// Returns `None` when there is nothing to check (null params / null
/// Environment pointer, or the parameters header itself unreadable) and
/// `Some(Err(..))` when an Environment pointer IS set but its block cannot
/// be walked safely (unreadable, unbounded — the caller fails closed).
///
/// # Safety
/// `params` must point to caller-process memory for the duration of the
/// call. Every dereference is clamped through `readable_region` first; no
/// guest-controlled length is followed unclamped.
unsafe fn read_guard_env_entries(
    params: *mut c_void,
) -> Option<Result<Vec<(String, String)>, &'static str>> {
    const ENVIRONMENT_OFFSET: usize = 0x80;
    // Clamp the header read itself: a guest hand-crafting params could point
    // it at a region shorter than 0x88 bytes.
    let Some((pbase, plen)) = crate::proc_guard::readable_region(params as *const c_void) else {
        return None;
    };
    let poff = params as usize - pbase as usize;
    if plen.saturating_sub(poff) < ENVIRONMENT_OFFSET + std::mem::size_of::<*const u16>() {
        return None;
    }
    // SAFETY: readable_region confirmed params..params+0x88 is committed and
    // readable, so the Environment pointer read is in-bounds.
    let env_ptr = *((params as *const u8).add(ENVIRONMENT_OFFSET) as *const *const u16);
    if env_ptr.is_null() {
        return Some(Ok(Vec::new()));
    }
    let Some((base, len)) = crate::proc_guard::readable_region(env_ptr as *const c_void) else {
        return Some(Err("child environment block unreadable"));
    };
    let off = env_ptr as usize - base as usize;
    let avail_chars = len.saturating_sub(off) / 2;
    // SAFETY: chars is bounded by the readable region returned above.
    let chars: &[u16] =
        std::slice::from_raw_parts(env_ptr, avail_chars.min(MAX_GUARD_ENV_CHARS));

    let mut entries = Vec::new();
    let mut cur = 0usize;
    while cur < chars.len() {
        let Some(rel_end) = chars[cur..].iter().position(|&c| c == 0) else {
            // Region exhausted without a terminator — unbounded block.
            return Some(Err("child environment block unbounded (no NUL terminator)"));
        };
        let entry = &chars[cur..cur + rel_end];
        cur += rel_end + 1;
        if entry.is_empty() {
            break; // double-NUL: end of block
        }
        let Some(eq) = entry.iter().position(|&c| c == b'=' as u16) else {
            continue; // not NAME=VALUE — ignore, same as RTL does
        };
        let name = String::from_utf16_lossy(&entry[..eq]).to_ascii_lowercase();
        if matches!(
            name.as_str(),
            // Security config — denied on presence alone (S02).
            "fs_sandbox_guard"
                | "fs_sandbox_allow_rwx"
                | "fs_sandbox_disable_hooks"
                | "fs_sandbox_pipe"
                | "fs_sandbox_dll"
                | "fs_sandbox_cwd"
                | "fs_sandbox_root"
                // Compare-to-snapshot inputs.
                | "fs_sandbox_no_track"
                | "fs_sandbox_section"
        ) {
            let value = String::from_utf16_lossy(&entry[eq + 1..]);
            entries.push((name, value));
        }
    }
    Some(Ok(entries))
}

/// Bound per-read chunk for remote image scans: it bounds MEMORY, not
/// coverage — every byte of the requested range is read and decoded exactly
/// once (plus the 15-byte instruction overlap below), regardless of section
/// size. S06 gap 4 (XA review 2026-09-20): replaces the silent
/// `min(64 MiB)` truncation whose tail of a large section went unscanned.
/// Residual: a hostile image with an enormous claimed section size can cost
/// scan TIME (the read fails closed at the first unmapped page), never
/// unbounded scan memory.
const REMOTE_SCAN_CHUNK_BYTES: usize = 16 * 1024 * 1024;

/// Longest possible x86-64 instruction — chunk overlap so an instruction
/// straddling a chunk boundary is still decoded by the earlier pass
/// (same discipline as the memory guard's chunked region scan).
const REMOTE_SCAN_CHUNK_OVERLAP: usize = 15;

/// Read+decode `[base, base + size)` out of the child image in bounded
/// chunks. Any read failure propagates — fail closed: the child must not
/// run over an image we could not fully check.
fn scan_remote_region(
    proc: HANDLE,
    base: usize,
    size: usize,
) -> Result<Vec<policy::scan::SyscallHit>, String> {
    let mut hits = Vec::new();
    let mut off = 0usize;
    while off < size {
        let n = (size - off).min(REMOTE_SCAN_CHUNK_BYTES);
        let ext = (n + REMOTE_SCAN_CHUNK_OVERLAP).min(size - off);
        let mut buf = vec![0u8; ext];
        read_remote_bytes(proc, base + off, &mut buf)?;
        for h in policy::scan::find_direct_syscalls_multi_entry(&buf, (base + off) as u64) {
            hits.push(policy::scan::SyscallHit { offset: off + h.offset, kind: h.kind });
        }
        off += n;
    }
    Ok(hits)
}

/// Scan the PE image mapped in `proc` for direct `syscall`/`sysenter`/`int 2eh`
/// instructions (the launcher's `pre_launch_scan` semantics, in-hook).
///
/// Errors are described by the returned message but share one caller policy:
/// the child must not run (fail closed). An image we cannot read is as
/// unacceptable as one we read and refused — the spawner controls the child
/// handle's access mask and could otherwise request just enough access for
/// injection (VM_OPERATION/VM_WRITE) while denying VM_READ to skip the scan.
pub(super) fn scan_image_for_direct_syscalls(proc: HANDLE) -> Result<(), String> {
    #[allow(dead_code)] // reserved fields mirror the kernel struct layout
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
        u32,         // ProcessInformationClass (0 = ProcessBasicInformation)
        *mut c_void, // ProcessInformation
        u32,         // ProcessInformationLength
        *mut u32,    // ReturnLength
    ) -> NTSTATUS;

    static QIP: OnceLock<Option<FnNtQueryInformationProcess>> = OnceLock::new();
    let qip = QIP.get_or_init(|| {
        // SAFETY: ntdll_export returns the real ntdll export address matching
        // the FnNtQueryInformationProcess ABI.
        let addr = unsafe { ntdll_export("NtQueryInformationProcess\0".as_bytes())? };
        // SAFETY: addr is the real NtQueryInformationProcess export.
        Some(unsafe { std::mem::transmute(addr as usize) })
    });
    let qip_fn = qip.ok_or_else(|| "NtQueryInformationProcess unavailable".to_string())?;

    let mut pbi = std::mem::MaybeUninit::<PROCESS_BASIC_INFORMATION>::uninit();
    // SAFETY: pbi is valid for size_of writes; proc is a live process handle.
    let status = unsafe {
        qip_fn(
            proc,
            0,
            pbi.as_mut_ptr() as *mut c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            std::ptr::null_mut(),
        )
    };
    if status < 0 {
        return Err(format!("NtQueryInformationProcess failed: 0x{:08x}", status as u32));
    }
    // SAFETY: status >= 0 means the kernel wrote the full struct.
    let peb_base = unsafe { (*pbi.as_ptr()).peb_base_address } as usize;
    if peb_base == 0 {
        return Err("PEB base address is null".into());
    }

    let mut image_base_bytes = [0u8; 8];
    read_remote_bytes(proc, peb_base + 0x10, &mut image_base_bytes)?;
    let image_base = usize::from_le_bytes(image_base_bytes);
    if image_base == 0 {
        return Err("image base is null".into());
    }

    // DOS + NT headers + section table fit in the first page.
    let mut pe_headers = [0u8; 4096];
    read_remote_bytes(proc, image_base, &mut pe_headers)?;
    // S06 gap 3 (XA review 2026-09-20): scan EVERY executable section, not
    // just ".text" — a child image can carry additional
    // IMAGE_SCN_MEM_EXECUTE sections.
    let exec_sections = policy::scan::pe_executable_sections(&pe_headers);
    if exec_sections.is_empty() {
        return Err("no executable section in child image".to_string());
    }

    for section in &exec_sections {
        let sec_base = image_base + section.virtual_address as usize;
        let hits = scan_remote_region(proc, sec_base, section.virtual_size as usize)?;
        if hits.is_empty() {
            continue;
        }
        let summary: Vec<String> = hits
            .iter()
            .take(5)
            .map(|h| format!("{} @ +0x{:x}", h.kind, h.offset))
            .collect();
        return Err(format!(
            "{} direct syscall instruction(s) in child executable section at RVA 0x{:x} ({}, …)",
            hits.len(),
            section.virtual_address,
            summary.join(", ")
        ));
    }
    Ok(())
}

/// ReadProcessMemory with a full-length check (short reads are an error).
fn read_remote_bytes(proc: HANDLE, addr: usize, buf: &mut [u8]) -> Result<(), String> {
    let mut read: usize = 0;
    // SAFETY: buf is valid for buf.len() bytes; addr is in the target's
    // address space (PEB or the mapped image — both committed while the
    // process exists).
    let ok = unsafe {
        winapi::um::memoryapi::ReadProcessMemory(
            proc,
            addr as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            &mut read,
        )
    };
    if ok == 0 {
        return Err(format!("ReadProcessMemory failed at 0x{addr:x}"));
    }
    if read != buf.len() {
        return Err(format!("short read at 0x{addr:x}: {read} of {}", buf.len()));
    }
    Ok(())
}

const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u32 = 0x0000_0001;

pub(super) unsafe extern "system" fn hook_nt_create_user_process(
    process_handle: *mut HANDLE,
    thread_handle: *mut HANDLE,
    process_desired_access: ACCESS_MASK,
    thread_desired_access: ACCESS_MASK,
    process_object_attributes: *mut OBJECT_ATTRIBUTES,
    thread_object_attributes: *mut OBJECT_ATTRIBUTES,
    process_flags: u32,
    thread_flags: u32,
    process_parameters: *mut c_void,
    create_info: *mut c_void,
    attribute_list: *mut c_void,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return crate::hooks::nt_call_original!(
            &HOOK_NT_CREATE_USER_PROCESS,
            "NtCreateUserProcess",
            (process_handle, thread_handle,
             process_desired_access, thread_desired_access,
             process_object_attributes, thread_object_attributes,
             process_flags, thread_flags,
             process_parameters, create_info, attribute_list)
        );
    };

    // --- proc_guard: denylisted executables ---
    if let Some(img) = crate::proc_guard::extract_image_path(process_parameters) {
        if crate::proc_guard::is_denylisted(&img) {
            if is_trace() {
                ipc_log(ipc::LogLevel::Trace,
                    format!("proc_spawn_blocked: {img}"));
            }
            return STATUS_ACCESS_DENIED;
        }
    }

    // --- proc_guard: parent-PID spoofing ---
    if !attribute_list.is_null() {
        if crate::proc_guard::attribute_list_contains_parent_process(attribute_list) {
            let img = crate::proc_guard::extract_image_path(process_parameters)
                .unwrap_or_else(|| "(unknown)".into());
            if is_trace() {
                ipc_log(ipc::LogLevel::Trace,
                    format!("proc_parent_spoof_blocked: {img}"));
            }
            return STATUS_ACCESS_DENIED;
        }
    }

    // --- proc_guard: explicit handle-list inheritance ---
    if !attribute_list.is_null() {
        if crate::proc_guard::attribute_list_contains_handle_list(attribute_list) {
            if is_trace() {
                ipc_log(ipc::LogLevel::Trace,
                    "proc_handle_list_blocked".into());
            }
            return STATUS_ACCESS_DENIED;
        }
    }

    // Force the child to start suspended so we can inject before it runs.
    let forced_flags = thread_flags | THREAD_CREATE_FLAGS_CREATE_SUSPENDED;
    let originally_suspended = (thread_flags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED) != 0;

    // Log EVERY spawn attempt with the target exe, before the syscall. Critical
    // diagnostic: a spawn_attempt without a matching `hello` event later means
    // the child was created but hook.dll injection did not initialise it (e.g.
    // cmd.exe's DllMain interferes — known limitation). Without this entry the
    // log shows children=0 and the cause is invisible.
    let spawn_target = extract_child_exe(process_parameters);
    let parent_pid = GetCurrentProcessId();
    ipc_log(ipc::LogLevel::Info,
        format!("spawn_attempt: parent={parent_pid} target={spawn_target}"));

    // Audit 2026-09-19 High: the environment block is guest-writable. A
    // sandboxed process can SetEnvironmentVariable a forged guard config and
    // spawn a child that inherits it — the child's hook.dll would install
    // with the memory guard disabled. Deny the spawn before the child exists
    // unless the inherited guard settings match the values WE captured at
    // our own install.
    if let Some(reason) = child_guard_env_violation(process_parameters) {
        ipc_log(ipc::LogLevel::Error,
            format!("child_env_guard_forged: parent={parent_pid} target={spawn_target}: {reason}; spawn denied"));
        return STATUS_ACCESS_DENIED;
    }

    // C0 diagnostic: when the target EXE is overlay-managed (the spawn-overlay-
    // redirect case), dump the PS_ATTRIBUTE_LIST entries so we can confirm the
    // PsAttributeImageName record (number 5) is present and read its Value
    // convention (raw PWSTR + byte Size vs a UNICODE_STRING pointer). This is
    // evidence-gathering BEFORE the C2 patch — it must not guess the convention.
    if is_trace() && !spawn_target.is_empty() {
        let vt = spawn_target.to_ascii_lowercase();
        let decision = decide(&vt, false);
        if matches!(decision.mode, policy::Mode::Cow | policy::Mode::Mock) {
            crate::proc_guard::dump_attr_list_for_overlay_spawn(attribute_list, &spawn_target);
        }
    }

    // If the EXE only exists in the CoW overlay, the kernel image loader would
    // fail with STATUS_PATH_NOT_FOUND. ImagePathOverlayGuard rewrites the
    // PsAttributeImageName record (number 5) in the attribute list to point at
    // the overlay copy for the duration of the syscall — the loader then maps
    // the overlay bytes directly, with NOTHING written to the host. This is the
    // principled solution (no materialize, no host write). See the guard's
    // docs for the full rationale.
    let _img_guard = unsafe {
        ImagePathOverlayGuard::new(process_parameters, create_info, attribute_list)
    };

    let status = crate::hooks::nt_call_original!(
        &HOOK_NT_CREATE_USER_PROCESS,
        "NtCreateUserProcess",
        (process_handle, thread_handle,
         process_desired_access, thread_desired_access,
         process_object_attributes, thread_object_attributes,
         process_flags, forced_flags,
         process_parameters, create_info, attribute_list)
    );

    if status < 0 {
        ipc_log(ipc::LogLevel::Warn,
            format!("spawn_failed: parent={parent_pid} target={spawn_target} status=0x{:08x}", status as u32));
        return status;
    }

    let proc_h = if process_handle.is_null() { return status; } else { *process_handle };
    let thr_h = if thread_handle.is_null() { return status; } else { *thread_handle };

    if proc_h.is_null() || thr_h.is_null() {
        return status;
    }

    // SAFETY: proc_h is a valid process handle returned by NtCreateUserProcess.
    let child_pid = GetProcessId(proc_h);

    // P1-01: scan the child's mapped image for direct syscall instructions
    // BEFORE it can run. The launcher scans the root target only, so without
    // this every process below the root keeps the SysWhispers/Hell's Gate
    // bypass open. Fail closed on BOTH detection and scan failure — terminate,
    // exactly like the launcher's pre_launch_scan refusal path.
    if child_scan_enabled(crate::trusted_boot::trusted_guard()) {
        if let Err(reason) = scan_image_for_direct_syscalls(proc_h) {
            ipc_log(
                ipc::LogLevel::Error,
                format!("child pre-launch scan refused pid={child_pid} target={spawn_target}: {reason}; terminating"),
            );
            // SAFETY: proc_h is the valid PROCESS handle returned moments ago
            // by NtCreateUserProcess; TerminateProcess never blocks. Exit code 1
            // signals "killed by sandbox" to anyone waiting on the process.
            unsafe { winapi::um::processthreadsapi::TerminateProcess(proc_h, 1) };
            return status;
        }
    }

    // Local authorization record — MUST precede inject_via_apc. memory_guard's
    // cross-process gates (NtAllocateVirtualMemory / NtProtectVirtualMemory /
    // NtWriteVirtualMemory) consult process_tracker::is_owned_child(target_pid)
    // for exactly the writes injection performs into the child: without the
    // record, inject_via_apc's VirtualAllocEx lands in the foreign-process
    // branch (terminate-if-executable — one protect-flag refactor away from a
    // self-terminating parent on every spawn) and WriteProcessMemory loses its
    // is_owned_child fast path and gets opcode-scanned on every spawn. This is
    // a purely local table write — no pipe I/O — so it does not widen the
    // pre-injection window (P0-04 is about the blocking IPC round-trips only).
    let child_exe = extract_child_exe(process_parameters);
    if child_pid != 0 {
        // Capture the creation-time fingerprint from the live handle we already
        // hold (M2: source-capture makes the PID-reuse defense always engage).
        // SAFETY: proc_h is the valid process handle returned by NtCreateUserProcess.
        let create_time = unsafe { crate::process_tracker::create_time_from_handle(proc_h) };
        // FS_SANDBOX_NO_TRACK moved here from process_tracker::mark_spawned
        // (review XA 2026-09-20, S02): the tracker must not consult the
        // guest-forgeable environment; the install-time snapshot decides.
        if !GUARD_ENV.get().map(|s| s.no_track).unwrap_or(false) {
            crate::process_tracker::mark_spawned(child_pid, parent_pid, child_exe.clone(), create_time);
        }
    }

    // S02 #3 (review XA 2026-09-20): per-child bootstrap acknowledgement.
    // APC injection success only proves LoadLibraryW was QUEUED — not that
    // hook.dll loaded and its guard is installed in THIS child. Create a
    // kernel Event with an unguessable per-child name here (trusted parent
    // code, 128-bit BCryptGenRandom suffix — the launcher's root-event
    // technique, without its predictable fallback: a guessable ack name would
    // let a same-session process preempt-signal it and fake protection). The
    // name rides into the child's environment through the same cross-process
    // env-block append that carries FS_SANDBOX_SECTION (below), so nothing
    // guest-suppliable can forge it: the spawn gate above ran on the ORIGINAL
    // guest environment BEFORE the syscall, and this variable is appended
    // afterwards, directly by us.
    let mut inject_failed = false;
    let child_ack = match crate::init_ack::create_child_init_ack(child_pid) {
        Ok(ack) => ack,
        Err(e) => {
            ipc_log(
                ipc::LogLevel::Error,
                format!("child ack event create failed pid={child_pid}: {e}; terminating sandbox-escape candidate"),
            );
            // SAFETY: proc_h is the valid PROCESS handle returned moments ago
            // by NtCreateUserProcess; TerminateProcess never blocks. Exit code 1
            // signals "killed by sandbox" to anyone waiting on the process.
            unsafe { winapi::um::processthreadsapi::TerminateProcess(proc_h, 1) };
            return status;
        }
    };

    // P0-04: inject BEFORE any blocking pipe round-trips. The child and its
    // suspended main thread are visible system-wide right after the syscall,
    // and ResumeThread is not hooked, so the pre-injection window must stay
    // down to the APC queue alone; the registration calls moved BELOW the ack
    // wait, so a child that never confirms its own protection is terminated
    // before the launcher ever hears about it.
    //
    // If injection fails the child process ALREADY exists (suspended, no user
    // code executed yet) and would escape the sandbox once resumed. Terminate
    // it before resume — fail closed. Registration and resume are skipped for
    // a child we just killed: bookkeeping for a dead PID tells the launcher
    // nothing it can act on.
    match DLL_PATH.get() {
        Some(dll_path) => {
            // Env pairs delivered through the injection channel: the
            // per-session section name (re-asserted by every spawn) plus the
            // per-child ack event name — one remote env-block write pass.
            let mut extra_env: Vec<(&str, &str)> = Vec::new();
            if let Some(section) = crate::ipc_client::session_section_name() {
                extra_env.push((inject::SECTION_ENV_VAR, section));
            }
            extra_env.push((crate::init_ack::CHILD_INIT_EVENT_ENV, child_ack.name()));
            if let Err(e) = inject::inject_via_apc(proc_h, thr_h, dll_path, &extra_env) {
                ipc_log(
                    ipc::LogLevel::Error,
                    format!("APC inject failed pid={child_pid}: {e}; terminating sandbox-escape candidate"),
                );
                // SAFETY: proc_h is the valid PROCESS handle returned moments ago
                // by NtCreateUserProcess; TerminateProcess never blocks. Exit code 1
                // signals "killed by sandbox" to anyone waiting on the process.
                unsafe { winapi::um::processthreadsapi::TerminateProcess(proc_h, 1) };
                inject_failed = true;
            }
        }
        None => {
            // Fail-closed injection (review XA 2026-09-20, S02): with no
            // trusted DLL_PATH there is no way to protect the child — the
            // old code silently resumed an UNHOOKED child here. Kill it
            // exactly like an inject failure.
            ipc_log(
                ipc::LogLevel::Error,
                format!("no trusted DLL_PATH — cannot protect child; terminating pid={child_pid}"),
            );
            // SAFETY: proc_h is the valid PROCESS handle returned moments ago
            // by NtCreateUserProcess; TerminateProcess never blocks. Exit code 1
            // signals "killed by sandbox" to anyone waiting on the process.
            unsafe { winapi::um::processthreadsapi::TerminateProcess(proc_h, 1) };
            inject_failed = true;
        }
    }

    // Resume if the caller did not want a suspended thread — but skip if we
    // just killed the child; there is nothing to resume in a dead process and
    // ResumeThread would only return an error.
    let mut ack_failed = false;
    if !originally_suspended && !inject_failed {
        let mut suspend_count: u32 = 0;
        // SAFETY: thr_h is a valid thread handle; NtResumeThread is always present.
        ntapi::ntpsapi::NtResumeThread(thr_h, &mut suspend_count);

        // S02 #3: bounded wait for THIS child's own "guard installed" signal.
        // The queued APC fires before the child's entry point once the initial
        // thread runs, so a healthy child acks within milliseconds; the 5s
        // budget mirrors the launcher's root handshake. A guest-requested
        // CREATE_SUSPENDED child is NOT resumed here (its main thread stays
        // suspended, so it cannot act unprotected): its ack fires from its own
        // install_hooks whenever the guest resumes it, before any child user
        // code runs — no wait, no timeout, nothing to fail closed.
        if !child_ack.wait_for_ack(crate::init_ack::CHILD_INIT_ACK_TIMEOUT_MS) {
            ipc_log(
                ipc::LogLevel::Error,
                format!("child bootstrap ack timeout pid={child_pid} target={spawn_target}: guard never confirmed; terminating"),
            );
            // SAFETY: proc_h is the valid PROCESS handle returned moments ago
            // by NtCreateUserProcess; TerminateProcess never blocks. Exit code 1
            // signals "killed by sandbox" to anyone waiting on the process.
            unsafe { winapi::um::processthreadsapi::TerminateProcess(proc_h, 1) };
            ack_failed = true;
        }
    }

    // Launcher bookkeeping — the two blocking IPC round-trips — runs LAST,
    // strictly after injection (P0-04) and after the ack wait: a child that
    // failed to bootstrap was already terminated, and a dead/never-running
    // child must not be registered — bookkeeping for it tells the launcher
    // nothing it can act on. The pipe server tolerates a child hello arriving
    // before these records (kernel-vouched parent walk, pipe_server/ownership.rs).
    if child_pid != 0 && !inject_failed && !ack_failed {
        ipc_register_child(child_pid);
        ipc_spawned_child(parent_pid, child_pid, child_exe);
    }

    status
}