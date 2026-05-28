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
///
/// Returns `Ok(())` on success or an error string for logging.
pub fn inject_via_apc(
    process: HANDLE,
    thread: HANDLE,
    dll_path: &str,
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

    // ObjectNameInformation layout: UNICODE_STRING at offset 0.
    // UNICODE_STRING: Length(u16) + MaximumLength(u16) + [pad u32 on x64] + Buffer(*mut u16).
    // We read Length and Buffer via the ObjectNameInfo repr we declared above.
    let info = buf.as_ptr() as *const ObjectNameInfo;
    let len_bytes = (*info).length as usize; // byte count, not char count
    let char_count = len_bytes / 2;
    if char_count == 0 {
        return None;
    }

    // Buffer pointer is valid inside our `buf` allocation for `char_count` u16s.
    let buf_ptr = (*info).buffer;
    if buf_ptr.is_null() {
        return None;
    }

    // SAFETY: `buf_ptr` points inside `buf` which is valid for `buf_len` bytes;
    // `char_count` * 2 <= len_bytes <= returned <= buf_len.
    let slice = std::slice::from_raw_parts(buf_ptr, char_count);
    Some(slice.to_vec())
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

