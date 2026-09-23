// DLL injection into a child process via NtQueueApcThread + LoadLibraryW.
// Called from the NtCreateUserProcess hook after the child is created suspended.
//
// Manually declares NtQueueApcThread and OBJECT_NAME_INFORMATION because
// ntapi 0.4 does not expose them in a stable, feature-gated way on all
// configurations we rely on.

// Use winapi's c_void to match winapi function signatures.
use winapi::ctypes::c_void;
use winapi::shared::ntdef::HANDLE;
use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress};
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory};
use winapi::um::winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE};

// ---------------------------------------------------------------------------
// Manual declaration of NtQueueApcThread (not in ntapi 0.4 public surface
// in the form we need here).
// ---------------------------------------------------------------------------

/// OBJECT_NAME_INFORMATION layout (manually declared; offset 0 = UNICODE_STRING).
/// Used only in resolve_handle_path; kept local to this module.
#[repr(C)]
pub(crate) struct ObjectNameInfo {
    // UNICODE_STRING: Length(u16), MaximumLength(u16), padding(u32 on x64), Buffer(*mut u16)
    pub(crate) length: u16,
    pub(crate) maximum_length: u16,
    _pad: u32,
    pub(crate) buffer: *mut u16,
    // Followed by the string data inline — we over-allocate the buffer.
}

/// NtQueueApcThread signature.
/// Declared manually because ntapi 0.4 may not expose it unconditionally.
type FnNtQueueApcThread = unsafe extern "system" fn(
    thread_handle: HANDLE,
    apc_routine: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void),
    apc_argument1: *mut c_void,
    apc_argument2: *mut c_void,
    apc_argument3: *mut c_void,
) -> i32;

/// Inject hook.dll into a process by queuing an APC that calls LoadLibraryW.
///
/// # Arguments
/// * `process` – handle to the target process (must have PROCESS_VM_WRITE |
///               PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD).
/// * `thread`  – handle to the initial (suspended) thread of the target process.
/// * `dll_path` – absolute Windows path to hook.dll (e.g. `C:\path\hook.dll`).
/// * `extra_env` – NAME=VALUE pairs appended to the child's environment
///   block before any guest code runs (session section name, per-child
///   ack event name).
///
/// Returns `Ok(())` on success or an error string for logging.
pub fn inject_via_apc(
    process: HANDLE,
    thread: HANDLE,
    dll_path: &str,
    extra_env: &[(&str, &str)],
) -> Result<(), String> {
    // Encode the DLL path as null-terminated UTF-16.
    let mut wide: Vec<u16> = dll_path.encode_utf16().collect();
    wide.push(0);
    let byte_len = wide.len() * 2;

    // Resolve the address of LoadLibraryW in the *current* process.
    // On modern Windows, kernel32.dll is mapped at the same base in all
    // processes (ASLR is per-boot, not per-process for system DLLs).
    let load_lib_addr: usize = unsafe {
        // SAFETY: literal ASCII name, null-terminated — always valid.
        let k32_name: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
        let hmod = GetModuleHandleW(k32_name.as_ptr());
        if hmod.is_null() {
            return Err("GetModuleHandleW(kernel32.dll) failed".into());
        }
        // SAFETY: hmod is valid, proc name is a valid ASCII literal.
        let proc = GetProcAddress(hmod, b"LoadLibraryW\0".as_ptr() as *const i8);
        if proc.is_null() {
            return Err("GetProcAddress(LoadLibraryW) failed".into());
        }
        proc as usize
    };

    // Allocate memory in the target process for the DLL path string.
    let remote_buf: *mut c_void = unsafe {
        // SAFETY: process handle is valid; we commit+reserve in one call.
        VirtualAllocEx(
            process,
            std::ptr::null_mut(),
            byte_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remote_buf.is_null() {
        return Err("VirtualAllocEx failed".into());
    }

    // Write the UTF-16 path into the remote buffer.
    let write_ok = unsafe {
        // SAFETY: remote_buf points to `byte_len` bytes of writable memory
        // we just allocated; wide.as_ptr() is valid for `byte_len` bytes.
        WriteProcessMemory(
            process,
            remote_buf,
            wide.as_ptr() as *const c_void,
            byte_len,
            std::ptr::null_mut(),
        )
    };
    if write_ok == 0 {
        unsafe {
            // SAFETY: remote_buf was successfully allocated above.
            VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
        }
        return Err("WriteProcessMemory failed".into());
    }

    // Deliver injected variables through the injection channel: append them
    // to the suspended child's environment block. This runs before any guest
    // code executes, so the values cannot be intercepted or forged, and they
    // reach env-scrubbed children (MSYS2 first-run helpers) exactly like the
    // DLL path above does. Today's callers inject the per-session section
    // name (re-asserted by every spawn) and the per-child bootstrap ack event
    // name (review XA 2026-09-20, S02 #3). On failure the APC is never queued
    // and the caller terminates the child: a hooked process without the
    // session name could only fail closed later (no pipe name ⇒
    // self-termination), so failing early is strictly cleaner.
    if !extra_env.is_empty() {
        if let Err(e) = patch_child_env_pairs(process, extra_env) {
            unsafe {
                // SAFETY: remote_buf was successfully allocated above; the
                //         APC was never queued, so nothing in the child can
                //         still be reading it.
                VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
            }
            return Err(format!("env patch failed: {e}"));
        }
    }

    // Resolve NtQueueApcThread dynamically from ntdll.
    let nt_queue_apc: FnNtQueueApcThread = unsafe {
        // SAFETY: literal name, always present in ntdll.dll on Windows NT.
        let ntdll_name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let hntdll = GetModuleHandleW(ntdll_name.as_ptr());
        if hntdll.is_null() {
            VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
            return Err("GetModuleHandleW(ntdll.dll) failed".into());
        }
        let fn_ptr =
            GetProcAddress(hntdll, b"NtQueueApcThread\0".as_ptr() as *const i8);
        if fn_ptr.is_null() {
            VirtualFreeEx(process, remote_buf, 0, MEM_RELEASE);
            return Err("GetProcAddress(NtQueueApcThread) failed".into());
        }
        // SAFETY: fn_ptr is the real NtQueueApcThread export from ntdll;
        // usize intermediate avoids direct fn-pointer transmute which is
        // technically UB without going through an integer type.
        let fn_usize = fn_ptr as usize;
        std::mem::transmute(fn_usize)
    };

    // Build the APC routine pointer from the LoadLibraryW address.
    // SAFETY: load_lib_addr is the real address of LoadLibraryW (extern "system",
    // fn(LPCWSTR) -> HMODULE). We cast it to the NtQueueApcThread APC-routine
    // shape fn(*mut c_void, *mut c_void, *mut c_void). On x64 MSVC ABI both use
    // the same calling convention; LoadLibraryW reads only RCX (arg1 = DLL path)
    // and ignores RDX/R8. This is the standard APC-injection technique; correctness
    // relies on x64 MSVC ABI stability, not on Rust type-system signature identity.
    // The transmute is NOT signature-compatible in the Rust sense — it is an
    // intentional ABI trick that is correct at the machine level only.
    let apc_fn: unsafe extern "system" fn(*mut c_void, *mut c_void, *mut c_void) =
        unsafe { std::mem::transmute(load_lib_addr) };

    // Queue the APC. When the thread is resumed and enters an alertable wait
    // (or is resumed into user-APC delivery), LoadLibraryW will be called
    // with the remote DLL path as its first argument.
    let status = unsafe {
        // SAFETY: thread handle is valid and suspended; remote_buf is
        // writable memory in `process` containing the UTF-16 DLL path.
        nt_queue_apc(
            thread,
            apc_fn,
            remote_buf,           // argument1 → lpLibFileName for LoadLibraryW
            std::ptr::null_mut(), // argument2 – unused
            std::ptr::null_mut(), // argument3 – unused
        )
    };

    // SAFETY / M-A6: remote_buf is LEAKED ON PURPOSE — it is intentionally
    // leaked because the child reads it asynchronously via the LoadLibraryW
    // APC after this function returns. Calling the remote-free API on
    // remote_buf here would free remote memory the child is about to
    // dereference, crashing the child (typically STATUS_DLL_INIT_FAILED or
    // an access violation in LoadLibraryW shortly after the initial thread
    // resumes).
    //
    // The small per-child leak (a few hundred bytes of UTF-16 path data) is
    // acceptable. A correct free would require a second APC queued after a
    // synchronization point, which adds significant complexity for marginal
    // benefit. This invariant is pinned by `intentional_leak_pin_tests` at
    // the bottom of this file — do NOT add a remote-buffer free between
    // `nt_queue_apc(...)` and `Ok(())` without updating those tests and
    // re-validating injection on Win10/11.

    if status < 0 {
        return Err(format!("NtQueueApcThread NTSTATUS={:#010x}", status as u32));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Session-name delivery (audit 2026-09-19, Critical #3 — companion to the
// launcher's random per-session section name)
// ---------------------------------------------------------------------------

/// Environment variable carrying the per-session random section name. The
/// launcher authors it for the root target; the spawn hook re-asserts it into
/// every child through [`patch_child_env_pairs`].
pub(crate) const SECTION_ENV_VAR: &str = "FS_SANDBOX_SECTION";

/// x64 layout constants. Documented, stable since Win7; the spawn hook's
/// `extract_child_exe` (params + 0x60 ImagePathName) and the launcher's
/// `get_image_base` (PEB + 0x10) already rely on the same fixed-offset
/// convention.
const PEB_PROCESS_PARAMETERS_OFFSET: usize = 0x20; // PEB -> ProcessParameters
const PARAMS_ENVIRONMENT_OFFSET: usize = 0x80; // RTL_USER_PROCESS_PARAMETERS -> Environment
const PARAMS_ENVIRONMENT_SIZE_OFFSET: usize = 0x3F0; // -> EnvironmentSize (Win8+)
const PARAMS_ENVIRONMENT_VALUES_SIZE_OFFSET: usize = 0x3F8; // -> EnvironmentValuesSize (Win8+)
/// Minimum x64 `RTL_USER_PROCESS_PARAMETERS` size covering every field we write.
const PARAMS_X64_LENGTH: usize = 0x400;
/// Upper bound for scanning the child's env block for its double-NUL
/// terminator (UTF-16 chars). A legitimate block stays far below this;
/// refusing to scan further keeps a malformed block from turning into an
/// unbounded cross-process read.
const MAX_ENV_BLOCK_CHARS: usize = 1 << 20; // 1 MiB of UTF-16

/// Build the replacement environment block: the surviving existing entries,
/// then the `entries` NAME=VALUE pairs in order, then the double-NUL
/// terminator.
///
/// Pure function so the wire format the child's environment consumers will
/// parse is unit-testable without a real child process. `existing` is the
/// block exactly as read from the child (terminator-inclusive). Inherited
/// entries whose NAME (case-insensitive) equals one of the appended names are
/// DROPPED: the appended pair is the freshest, parent-authored value, and
/// environment consumers return the FIRST match — for the per-child ack event
/// name a stale inherited copy must never shadow it. The result keeps one NUL
/// between entries and ends in exactly one `\0\0`.
fn env_block_bytes(existing: Option<&[u16]>, entries: &[(&str, &str)]) -> Vec<u8> {
    let appended_names: Vec<String> = entries
        .iter()
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect();
    let mut chars: Vec<u16> = Vec::new();
    if let Some(existing) = existing {
        // Walk NAME=VALUE entries split on single NULs; re-emit only the
        // survivors, each with its terminator NUL. An empty slice ends the
        // walk (double-NUL).
        let mut start = 0usize;
        while start < existing.len() {
            let Some(rel_end) = existing[start..].iter().position(|&c| c == 0) else {
                break; // unterminated tail — ignore, same as before
            };
            let entry = &existing[start..start + rel_end];
            start += rel_end + 1;
            if entry.is_empty() {
                break;
            }
            let keep = match entry.iter().position(|&c| c == '=' as u16) {
                Some(eq) => {
                    let name = String::from_utf16_lossy(&entry[..eq]).to_ascii_lowercase();
                    !appended_names.contains(&name)
                }
                None => true,
            };
            if keep {
                chars.extend_from_slice(entry);
                chars.push(0);
            }
        }
    }
    for (name, value) in entries {
        chars.extend(name.encode_utf16());
        chars.push('=' as u16);
        chars.extend(value.encode_utf16());
        chars.push(0); // entry terminator
    }
    chars.push(0); // block terminator
    let mut bytes = Vec::with_capacity(chars.len() * 2);
    for c in chars {
        bytes.extend_from_slice(&c.to_le_bytes());
    }
    bytes
}

/// ReadProcessMemory with a full-length check (short reads are an error).
fn read_remote_bytes(process: HANDLE, addr: usize, buf: &mut [u8]) -> Result<(), String> {
    let mut read: usize = 0;
    // SAFETY: buf is valid for buf.len() writes; addr is in the target's
    //         address space (PEB / ProcessParameters — committed while the
    //         suspended process exists).
    let ok = unsafe {
        winapi::um::memoryapi::ReadProcessMemory(
            process,
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

/// Append the `entries` NAME=VALUE pairs to the SUSPENDED child's
/// environment block, cross-process, in order.
///
/// This is the delivery channel for the per-session random section name
/// (audit 2026-09-19, Critical #3): every child — including env-scrubbed
/// ones such as MSYS2 first-run helpers — is written here before any guest
/// code runs, so the value cannot be intercepted or forged by the guest.
/// The hook reads the variable at DllMain install time via
/// GetEnvironmentVariableW, which walks PEB->ProcessParameters->Environment
/// live — exactly the pointer this function rewrites.
///
/// Inherited entries whose name equals one being appended are dropped first
/// (see env_block_bytes): the appended pair is the freshest, parent-authored
/// value, and GetEnvironmentVariableW / `std::env::var` return the FIRST
/// match in the block. Without the drop, a nested child could keep the stale
/// per-child ack name it inherited from ITS parent, signal a dead event, and
/// its own parent would time out.
///
/// Mechanics: read the child's PEB -> ProcessParameters -> Environment,
/// allocate a replacement block in the child, write old entries + our
/// entry, then repoint Environment (plus the Win8+ EnvironmentSize /
/// EnvironmentValuesSize fields). The old block is intentionally NOT freed:
/// it was allocated by the process-creation path inside the child and may
/// live under a heap we cannot safely VirtualFreeEx; a few KiB per child is
/// acceptable (same trade as the intentionally leaked DLL-path buffer).
///
/// Returns Ok(()) without doing anything for a WOW64 child: it cannot load
/// this x64 hook DLL anyway, so there is no config to deliver.
fn patch_child_env_pairs(process: HANDLE, entries: &[(&str, &str)]) -> Result<(), String> {
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
        usize,       // ProcessInformationClass (0 = ProcessBasicInformation)
        *mut c_void, // ProcessInformation
        u32,         // ProcessInformationLength
        *mut u32,    // ReturnLength
    ) -> i32;

    static QIP: std::sync::OnceLock<Option<FnNtQueryInformationProcess>> =
        std::sync::OnceLock::new();
    let qip = QIP.get_or_init(|| {
        let ntdll_name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        // SAFETY: literal ASCII name, null-terminated — always valid.
        let hntdll = unsafe { GetModuleHandleW(ntdll_name.as_ptr()) };
        if hntdll.is_null() {
            return None;
        }
        // SAFETY: hntdll is valid, proc name is a valid ASCII literal.
        let proc =
            unsafe { GetProcAddress(hntdll, b"NtQueryInformationProcess\0".as_ptr() as *const i8) };
        if proc.is_null() {
            return None;
        }
        // SAFETY: fn_ptr is the real NtQueryInformationProcess export; the
        //         usize intermediate avoids a direct fn-pointer transmute.
        let fn_usize = proc as usize;
        Some(unsafe { std::mem::transmute(fn_usize) })
    });
    let qip_fn = qip.ok_or_else(|| "NtQueryInformationProcess unavailable".to_string())?;

    let mut pbi = std::mem::MaybeUninit::<PROCESS_BASIC_INFORMATION>::uninit();
    // SAFETY: pbi is valid for size_of writes; process is a live child handle
    //         with full access (returned by NtCreateUserProcess moments ago).
    let status = unsafe {
        qip_fn(
            process,
            0,
            pbi.as_mut_ptr() as *mut c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            std::ptr::null_mut(),
        )
    };
    if status < 0 {
        return Err(format!("NtQueryInformationProcess failed: 0x{status:08x}"));
    }
    // SAFETY: status >= 0 means the kernel wrote the full struct.
    let peb_base = unsafe { (*pbi.as_ptr()).peb_base_address } as usize;
    if peb_base == 0 {
        return Err("PEB base address is null".into());
    }

    // ProcessParameters pointer (PEB + 0x20).
    let mut params_bytes = [0u8; 8];
    read_remote_bytes(process, peb_base + PEB_PROCESS_PARAMETERS_OFFSET, &mut params_bytes)?;
    let params = usize::from_le_bytes(params_bytes);
    if params == 0 {
        return Err("child ProcessParameters is null".into());
    }

    // WOW64 children use a 32-bit layout we do not write through (and cannot
    // load this x64 DLL anyway) — skip them explicitly.
    let mut wow64: usize = 0;
    // SAFETY: wow64 is a valid usize out-param; class 26 = ProcessWow64Information.
    let status = unsafe {
        qip_fn(process, 26, &mut wow64 as *mut usize as *mut c_void,
               std::mem::size_of::<usize>() as u32, std::ptr::null_mut())
    };
    if status < 0 {
        return Err(format!("ProcessWow64Information failed: 0x{status:08x}"));
    }
    if wow64 != 0 {
        return Ok(());
    }

    // Length (offset 0x00) spans the header PLUS the packed strings (0x726
    // observed), never exactly the 0x400 header — the old `== 0x400` test
    // skipped EVERY child, so no injected variable ever arrived. Require only
    // that the header covers every field written below.
    let mut len_bytes = [0u8; 4];
    read_remote_bytes(process, params, &mut len_bytes)?;
    let params_length = u32::from_le_bytes(len_bytes) as usize;
    if params_length < PARAMS_X64_LENGTH {
        return Err(format!("child ProcessParameters too short: 0x{params_length:x}"));
    }

    // Existing entries, if any. Read in 4 KiB chunks (the block may end well
    // before its surrounding allocation, and ReadProcessMemory fails whole
    // when it crosses an unreadable page) and stop at the double-NUL
    // terminator; the used prefix becomes the base of the new block.
    let existing: Option<Vec<u16>> = if env_is_null(process, params)? {
        None
    } else {
        let env_ptr = read_remote_usize(process, params + PARAMS_ENVIRONMENT_OFFSET)?;
        let mut chars: Vec<u16> = Vec::new();
        let mut terminated = false;
        while chars.len() < MAX_ENV_BLOCK_CHARS {
            let mut buf = [0u8; 4096]; // 2048 UTF-16 units per chunk
            if read_remote_bytes(process, env_ptr + chars.len() * 2, &mut buf).is_err() {
                break; // unreadable tail — stop with what we have
            }
            let old_len = chars.len();
            chars.extend(buf.chunks_exact(2).map(|p| u16::from_le_bytes([p[0], p[1]])));
            // `start` one before the append point so a pair spanning the
            // chunk boundary is still found.
            let start = old_len.saturating_sub(1);
            if let Some(pos) = chars[start..].windows(2).position(|w| w == [0, 0]) {
                chars.truncate(start + pos + 2);
                terminated = true;
                break;
            }
        }
        if !terminated {
            return Err("child env block not terminated within the scan bound".into());
        }
        Some(chars)
    };

    let new_block = env_block_bytes(existing.as_deref(), entries);
    let new_size = new_block.len();

    // SAFETY: process is a live child handle with full access; commit+reserve
    //         a replacement environment block in the suspended child.
    let remote_block = unsafe {
        VirtualAllocEx(
            process,
            std::ptr::null_mut(),
            new_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remote_block.is_null() {
        return Err("VirtualAllocEx (env block) failed".into());
    }

    // SAFETY: remote_block points to new_size writable bytes just allocated
    //         in the child; new_block is exactly new_size bytes.
    let write_ok = unsafe {
        WriteProcessMemory(
            process,
            remote_block,
            new_block.as_ptr() as *const c_void,
            new_size,
            std::ptr::null_mut(),
        )
    };
    if write_ok == 0 {
        unsafe {
            // SAFETY: remote_block was allocated above and nothing in the
            //         child can reference it yet (still suspended).
            VirtualFreeEx(process, remote_block, 0, MEM_RELEASE);
        }
        return Err("WriteProcessMemory (env block) failed".into());
    }

    // Repoint ProcessParameters.Environment (and the Win8+ size fields) at
    // the replacement block. Consumers either walk to the double-NUL or use
    // these fields to size the block; both now describe the same bytes.
    let patch = |addr: usize, bytes: &[u8]| -> Result<(), String> {
        let mut written: usize = 0;
        // SAFETY: addr is inside the child's ProcessParameters (committed,
        //         length-verified as 0x400 above); bytes is valid for
        //         bytes.len() reads.
        let ok = unsafe {
            WriteProcessMemory(
                process,
                addr as *mut c_void,
                bytes.as_ptr() as *const c_void,
                bytes.len(),
                &mut written,
            )
        };
        if ok == 0 || written != bytes.len() {
            return Err(format!("WriteProcessMemory failed at 0x{addr:x}"));
        }
        Ok(())
    };

    patch(params + PARAMS_ENVIRONMENT_OFFSET, &(remote_block as usize).to_le_bytes())?;
    patch(params + PARAMS_ENVIRONMENT_SIZE_OFFSET, &(new_size as u64).to_le_bytes())?;
    patch(
        params + PARAMS_ENVIRONMENT_VALUES_SIZE_OFFSET,
        &(new_size as u64).to_le_bytes(),
    )?;

    Ok(())
}

/// Read the Environment pointer at `params + 0x80` and report whether it is
/// null (a child may legitimately inherit no environment at all).
fn env_is_null(process: HANDLE, params: usize) -> Result<bool, String> {
    Ok(read_remote_usize(process, params + PARAMS_ENVIRONMENT_OFFSET)? == 0)
}

/// Read a native-pointer-sized value from the child.
fn read_remote_usize(process: HANDLE, addr: usize) -> Result<usize, String> {
    let mut buf = [0u8; 8];
    read_remote_bytes(process, addr, &mut buf)?;
    Ok(usize::from_le_bytes(buf))
}

/// Resolve the NT object name for an open handle using NtQueryObject.
///
/// Returns the full NT path (e.g. `\Device\HarddiskVolume3\foo.txt`) or None
/// on failure. Result is UTF-16 without null terminator.
///
/// # Safety
/// `handle` must be a valid, open HANDLE with at least
/// OBJECT_QUERY_INFORMATION access.
pub unsafe fn resolve_handle_path(handle: HANDLE) -> Option<Vec<u16>> {
    use ntapi::ntobapi::NtQueryObject;
    use ntapi::ntobapi::ObjectNameInformation;

    // Allocate a stack buffer large enough for most paths (32 KiB).
    // MAX_PATH in NT is 32767 UTF-16 code units = 65534 bytes.
    // We use a Vec to keep this off the stack (§B7: avoid large stack allocs).
    let buf_len = 65536usize;
    let mut buf: Vec<u8> = vec![0u8; buf_len];

    let mut returned: u32 = 0;

    // SAFETY: buf is valid for `buf_len` bytes; ObjectNameInformation = 1.
    let status = NtQueryObject(
        handle,
        ObjectNameInformation,
        buf.as_mut_ptr() as *mut _,
        buf_len as u32,
        &mut returned,
    );
    if status < 0 {
        return None;
    }

    // `returned` was previously ignored, so the parse below trusted the
    // UNICODE_STRING's own Length/Buffer fields with nothing to check them
    // against (audit 2026-09-19, Low — note the audit cites the launcher's
    // inject.rs, but that copy validates its query; the defect is here, in
    // the hook-side twin). Clamp to what the kernel actually wrote.
    let valid = (returned as usize).min(buf_len);

    // ObjectNameInformation layout: UNICODE_STRING at offset 0 — see
    // parse_object_name_info for why every field read there is unaligned.
    parse_object_name_info(buf.as_ptr(), valid)
}

/// Parse the OBJECT_NAME_INFORMATION a successful NtQueryObject wrote into
/// `buf` (a raw byte buffer we own as a `Vec<u8>`) into its UTF-16 name.
///
/// A `Vec<u8>` allocation guarantees only 1-byte alignment, and the
/// UNICODE_STRING sits at offset 0 of that buffer — so Length (@0), the
/// Buffer pointer (@8) and the WCHAR data the kernel inlines behind the
/// struct (@16, via the reported Buffer) are ALL potentially misaligned.
/// Every read here goes through read_unaligned; a plain `(*info).length`
/// dereference through a `*const ObjectNameInfo` (align 8) is UB on an odd
/// buffer and aborts under the debug alignment check.
///
/// Returns `None` for a zero Length or a null Buffer.
///
/// # SAFETY
/// `buf` must hold a well-formed OBJECT_NAME_INFORMATION as written by a
/// successful NtQueryObject into a buffer of at least `buf_len` bytes: the
/// reported Length bytes must be readable at the reported Buffer, which
/// points inside `buf`.
/// Decode an `OBJECT_NAME_INFORMATION` that the kernel wrote into our own
/// buffer.
///
/// `valid_len` is how many bytes the kernel reported writing. Every field is
/// checked against it: the header must fit, `Length` must fit behind the
/// header, and `Buffer` must point at an inline span that lies wholly inside
/// the same `valid_len` bytes. Without that the decode walked wherever
/// `Buffer` pointed for however many characters `Length` claimed — both of
/// which are just bytes in a buffer, trusted on a SAFETY comment rather than
/// verified.
unsafe fn parse_object_name_info(buf: *const u8, valid_len: usize) -> Option<Vec<u16>> {
    const HEADER: usize = std::mem::size_of::<ObjectNameInfo>();
    if valid_len < HEADER {
        return None;
    }

    let info = buf as *const ObjectNameInfo;
    // SAFETY: addr_of + read_unaligned projects the field in place (no
    // intermediate reference is minted) and tolerates any `buf` alignment.
    let len_bytes = std::ptr::addr_of!((*info).length).read_unaligned() as usize; // byte count, not char count
    let char_count = len_bytes / 2;
    if char_count == 0 || len_bytes > valid_len - HEADER {
        return None;
    }

    // SAFETY: addr_of + read_unaligned, as above — no alignment assumed.
    let buf_ptr = std::ptr::addr_of!((*info).buffer).read_unaligned();
    if buf_ptr.is_null() {
        return None;
    }

    // The kernel inlines the name behind the header, inside the very buffer we
    // handed it. Require exactly that: `[buf_ptr, buf_ptr + len_bytes)` must
    // sit within `[buf, buf + valid_len)`. A Buffer pointing outside means the
    // record is not the self-contained reply we asked for, so refuse it rather
    // than dereference it.
    let base = buf as usize;
    let start = buf_ptr as usize;
    let end = match start.checked_add(len_bytes) {
        Some(e) => e,
        None => return None,
    };
    if start < base + HEADER || end > base + valid_len {
        return None;
    }

    Some(
        (0..char_count)
            .map(|i| {
                // SAFETY: the span was just proven to lie inside `buf`, which
                // is valid for `valid_len` bytes; read_unaligned imposes no
                // alignment requirement.
                unsafe { buf_ptr.add(i).read_unaligned() }
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// M-A6 pin tests: protect the intentional remote-buffer leak in
// inject_via_apc from being silently "fixed" by a future maintainer.
//
// Background: VirtualAllocEx in the child + WriteProcessMemory + NtQueueApcThread
// is asynchronous. The child reads the buffer when the APC fires (after the
// child is resumed and enters an alertable wait / user-APC delivery point).
// If we VirtualFreeEx the buffer between queueing the APC and the child reading
// it, LoadLibraryW will dereference freed remote memory and crash the child
// (access violation, STATUS_DLL_INIT_FAILED or similar).
//
// The pre-APC error paths in inject_via_apc legitimately call VirtualFreeEx
// to avoid leaking on failure (the APC was never queued, so the child never
// reads the buffer). Those are correct. The forbidden pattern is a
// VirtualFreeEx call AFTER the NtQueueApcThread call returns success.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod intentional_leak_pin_tests {
    /// Pin test for M-A6: `inject_via_apc` deliberately does NOT call
    /// `VirtualFreeEx` on the remote buffer AFTER queueing the APC. The child
    /// reads the buffer via APC after this function returns; freeing the
    /// buffer here causes a child-side crash.
    ///
    /// If this test fails:
    /// - A maintainer added `VirtualFreeEx` to `inject_via_apc` after the
    ///   `NtQueueApcThread` call.
    /// - This is almost certainly a bug. Verify by running the e2e suite on
    ///   Win10/11; injection failures may manifest as STATUS_DLL_INIT_FAILED
    ///   or silent child crashes shortly after CreateProcess.
    /// - If the change is intentional (e.g., switched to a synchronous
    ///   injection model where the child finishes loading before we free),
    ///   update this test to reflect the new contract.
    ///
    /// Note: this is a textual scan and therefore fragile against heavy
    /// refactors. The two anchors it relies on are the `nt_queue_apc(` call
    /// and the trailing `Ok(())` of `inject_via_apc`. If those move,
    /// re-anchor the test rather than disabling it.
    #[test]
    fn inject_via_apc_does_not_free_remote_buf_after_apc_queue() {
        let src = include_str!("inject.rs");

        // Locate the function definition.
        let fn_start = src
            .find("pub fn inject_via_apc")
            .expect("inject_via_apc function must exist");

        // Locate the NtQueueApcThread call site (via the local fn-pointer
        // binding `nt_queue_apc(`).
        let queue_call = src[fn_start..]
            .find("nt_queue_apc(")
            .expect("inject_via_apc must call nt_queue_apc(...)");
        let queue_abs = fn_start + queue_call;

        // Locate the Ok(()) return of inject_via_apc. Use the first Ok(())
        // after the queue call — that is the success-path return.
        let ok_offset = src[queue_abs..]
            .find("Ok(())")
            .expect("inject_via_apc must return Ok(()) after queueing the APC");
        let ok_abs = queue_abs + ok_offset;

        // The forbidden region: everything between the queue call and the
        // success return. A free of the remote buffer here would free
        // memory the child still needs to read.
        let post_queue_raw = &src[queue_abs..ok_abs];

        // Strip line comments (// ...) so that future doc edits that mention
        // the forbidden API name in prose do not trip the scan. This is a
        // best-effort strip; block comments and string literals are not
        // expected in this region.
        let mut post_queue_code = String::with_capacity(post_queue_raw.len());
        for line in post_queue_raw.lines() {
            let code_part = match line.find("//") {
                Some(idx) => &line[..idx],
                None => line,
            };
            post_queue_code.push_str(code_part);
            post_queue_code.push('\n');
        }

        assert!(
            !post_queue_code.contains("VirtualFreeEx"),
            "inject_via_apc must NOT call VirtualFreeEx between NtQueueApcThread \
             and Ok(()) — the child reads remote_buf asynchronously via APC and \
             freeing it here crashes the child. See M-A6 pin justification above.\n\
             Offending region (between nt_queue_apc and Ok(()), comments stripped):\n\
             ---\n{post_queue_code}\n---"
        );
    }

    /// Pin test for M-A6: ensure the LEAK is documented near the alloc so
    /// future readers know the omission of `VirtualFreeEx` on the success path
    /// is intentional, not an oversight.
    #[test]
    fn inject_via_apc_documents_leak() {
        let src = include_str!("inject.rs").to_ascii_lowercase();
        let markers = ["leaked on purpose", "intentional", "intentionally leaked"];
        let has_marker = markers.iter().any(|m| src.contains(&m.to_ascii_lowercase()));
        assert!(
            has_marker,
            "inject_via_apc must document the intentional remote-buffer leak \
             with one of the marker phrases: {markers:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Unaligned-buffer regression (alignment-UB class)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod object_name_parsing_tests {
    use super::*;

    /// REGRESSION: a `Vec<u8>` allocation guarantees only 1-byte alignment,
    /// and resolve_handle_path parses OBJECT_NAME_INFORMATION straight out of
    /// it — so Length (@0), the Buffer pointer (@8) and the inlined name
    /// (@16) can all sit at odd addresses. Forcing the probe onto an odd
    /// base, the parse must still produce the exact name; the old plain
    /// `(*info).length` dereference through a `*const ObjectNameInfo` is UB
    /// on the odd base and aborts under the debug alignment check.
    #[test]
    fn parse_object_name_info_reads_unaligned_buffer() {
        let name: Vec<u16> = r"\Device\HarddiskVolume3\Mixed.TXT".encode_utf16().collect();
        // OBJECT_NAME_INFORMATION: UNICODE_STRING (16 bytes) + inline WCHARs.
        let body_len = 16 + name.len() * 2;
        let mut backing = vec![0u8; body_len + 512];
        let off = 1 - (backing.as_ptr() as usize % 2);
        assert_eq!(
            (backing.as_ptr() as usize + off) % 2,
            1,
            "probe buffer must start at an odd address",
        );
        let base = off;
        // Length: bytes of the name, excluding any NUL.
        backing[base..base + 2].copy_from_slice(&((name.len() * 2) as u16).to_le_bytes());
        // MaximumLength: includes NUL slack.
        backing[base + 2..base + 4].copy_from_slice(&(body_len as u16).to_le_bytes());
        // Buffer: points at the inline data behind the struct (inside `backing`).
        let inline_addr = backing.as_ptr() as usize + base + 16;
        backing[base + 8..base + 16].copy_from_slice(&(inline_addr as u64).to_le_bytes());
        for (i, u) in name.iter().enumerate() {
            backing[base + 16 + i * 2..base + 18 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        // SAFETY: backing[base..base+body_len] is a well-formed
        // OBJECT_NAME_INFORMATION whose Buffer points inside `backing`.
        let parsed = unsafe { parse_object_name_info(backing.as_ptr().add(base), body_len) };
        assert_eq!(
            parsed.expect("well-formed OBJECT_NAME_INFORMATION must parse"),
            name
        );
    }

    /// Zero Length and a non-zero Length with a null Buffer both map to None,
    /// matching the original inline behavior of resolve_handle_path.
    #[test]
    fn parse_object_name_info_rejects_empty_and_null() {
        let mut backing = vec![0u8; 256];
        // SAFETY: all-zero UNICODE_STRING header is a valid (empty) input.
        let parsed = unsafe { parse_object_name_info(backing.as_ptr(), backing.len()) };
        assert_eq!(parsed, None);

        // Non-zero Length with null Buffer.
        backing[0..2].copy_from_slice(&8u16.to_le_bytes());
        // SAFETY: header is valid; the null-Buffer rejection is the contract.
        let parsed = unsafe { parse_object_name_info(backing.as_ptr(), backing.len()) };
        assert_eq!(parsed, None);
    }

    /// Bounds checking against what the kernel actually wrote (audit
    /// 2026-09-19, Low — `returned` was ignored, so `Length` and `Buffer`
    /// were trusted on a SAFETY comment rather than verified).
    ///
    /// Three shapes must all be refused, and before the fix each was decoded:
    /// a `Length` larger than the reply, a `Buffer` pointing past the end of
    /// the reply, and a reply too short to even hold the header.
    #[test]
    fn parse_object_name_info_rejects_out_of_bounds_fields() {
        const HEADER: usize = std::mem::size_of::<ObjectNameInfo>();
        let name: Vec<u16> = "abcd".encode_utf16().collect();
        let body_len = HEADER + name.len() * 2;

        let build = |len_bytes: u16, buffer_at: usize| -> Vec<u8> {
            let mut b = vec![0u8; body_len + 512];
            b[0..2].copy_from_slice(&len_bytes.to_le_bytes());
            b[2..4].copy_from_slice(&(body_len as u16).to_le_bytes());
            let addr = b.as_ptr() as usize + buffer_at;
            b[8..16].copy_from_slice(&(addr as u64).to_le_bytes());
            for (i, u) in name.iter().enumerate() {
                b[HEADER + i * 2..HEADER + 2 + i * 2].copy_from_slice(&u.to_le_bytes());
            }
            b
        };

        // 1. Length claims far more than the kernel reported writing.
        let b = build(4096, HEADER);
        // SAFETY: `b` is valid for body_len bytes; the oversized Length is the input under test.
        assert_eq!(unsafe { parse_object_name_info(b.as_ptr(), body_len) }, None);

        // 2. Buffer points past the end of the valid region.
        let b = build((name.len() * 2) as u16, body_len + 256);
        // SAFETY: as above; the out-of-range Buffer must be refused, not followed.
        assert_eq!(unsafe { parse_object_name_info(b.as_ptr(), body_len) }, None);

        // 3. The reply is shorter than the header it claims to be.
        let b = build((name.len() * 2) as u16, HEADER);
        // SAFETY: as above; a truncated reply cannot be parsed.
        assert_eq!(unsafe { parse_object_name_info(b.as_ptr(), HEADER - 1) }, None);

        // Control: the same record with honest bounds still decodes.
        let b = build((name.len() * 2) as u16, HEADER);
        // SAFETY: well-formed, self-contained record.
        assert_eq!(unsafe { parse_object_name_info(b.as_ptr(), body_len) }, Some(name));
    }
}

#[cfg(test)]
mod env_delivery_tests {
    use super::*;

    const CHILD_INIT_EVENT_ENV_FOR_TEST: &str = "FS_SANDBOX_CHILD_INIT_EVENT";

    fn decode_block(block: &[u8]) -> String {
        let chars: Vec<u16> = block
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        String::from_utf16_lossy(&chars)
    }

    /// The block the child's environment consumers will parse: existing
    /// entries verbatim, then NAME=VALUE, then exactly one double-NUL.
    #[test]
    fn env_block_appends_entry_with_terminator() {
        let existing: Vec<u16> = "PATH=C:\\Windows\0TEMP=C:\\Temp\0\0"
            .encode_utf16()
            .collect();
        let block = env_block_bytes(
            Some(&existing),
            &[(SECTION_ENV_VAR, r"Local\WinRsBoxSession-abcd")],
        );
        let text = decode_block(&block);
        assert!(
            text.starts_with("PATH=C:\\Windows\0TEMP=C:\\Temp\0"),
            "existing entries must survive verbatim: {text:?}"
        );
        assert_eq!(
            text.matches("FS_SANDBOX_SECTION=").count(),
            1,
            "exactly one section entry may be appended: {text:?}"
        );
        assert!(
            text.contains("FS_SANDBOX_SECTION=Local\\WinRsBoxSession-abcd\0"),
            "the appended entry must be complete and NUL-terminated: {text:?}"
        );
        assert!(text.ends_with("\0\0"), "block must end in a double-NUL: {text:?}");
    }

    /// A child that inherited an empty (scrubbed) environment: no existing
    /// entries — the block is exactly our entry plus the terminator. This is
    /// the MSYS2 first-run case the section fallback exists for.
    #[test]
    fn env_block_handles_scrubbed_child() {
        let block = env_block_bytes(None, &[(SECTION_ENV_VAR, "Local\\WinRsBoxSession-x")]);
        assert_eq!(
            decode_block(&block),
            "FS_SANDBOX_SECTION=Local\\WinRsBoxSession-x\0\0"
        );
    }

    /// An existing block carrying extra trailing terminators is normalized:
    /// the result keeps the entries and ends in exactly one terminator pair.
    #[test]
    fn env_block_strips_trailing_terminators_before_append() {
        let existing: Vec<u16> = "A=B\0\0\0".encode_utf16().collect();
        let block = env_block_bytes(Some(&existing), &[("K", "V")]);
        assert_eq!(decode_block(&block), "A=B\0K=V\0\0");
    }

    /// A nested child inherits its PARENT's per-child ack env var; the spawn
    /// hook must overwrite it, not append a second entry — env consumers
    /// return the FIRST match, so a stale shadow would make the grandchild
    /// signal a dead event and its own parent time out.
    #[test]
    fn env_block_replaces_inherited_same_name_entry() {
        let existing: Vec<u16> = "FS_SANDBOX_CHILD_INIT_EVENT=Local\\stale\0PATH=C:\\x\0\0"
            .encode_utf16()
            .collect();
        let block = env_block_bytes(
            Some(&existing),
            &[(CHILD_INIT_EVENT_ENV_FOR_TEST, "Local\\fresh")],
        );
        assert_eq!(
            decode_block(&block),
            "PATH=C:\\x\0FS_SANDBOX_CHILD_INIT_EVENT=Local\\fresh\0\0",
            "the stale inherited ack entry must be dropped, not shadowed"
        );
    }

    /// Multiple pairs ride one remote write pass, in caller order.
    #[test]
    fn env_block_appends_pairs_in_order() {
        let existing: Vec<u16> = "A=B\0\0".encode_utf16().collect();
        let block = env_block_bytes(Some(&existing), &[("K1", "V1"), ("K2", "V2")]);
        assert_eq!(decode_block(&block), "A=B\0K1=V1\0K2=V2\0\0");
    }
}


#[cfg(test)]
#[path = "inject_env_tests.rs"]
mod inject_env_tests;
