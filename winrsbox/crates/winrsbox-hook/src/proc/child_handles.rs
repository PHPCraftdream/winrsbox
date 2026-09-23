// Own duplicates of spawned-child process handles, for identity checks on
// caller handles that carry no query rights (GetProcessId needs
// PROCESS_QUERY_LIMITED_INFORMATION; NtCompareObjects needs nothing).

use std::sync::Mutex;
use winapi::shared::ntdef::HANDLE;

/// (child pid, our SYNCHRONIZE-only duplicate of its process handle).
static HANDLES: Mutex<Vec<(u32, usize)>> = Mutex::new(Vec::new());

type FnNtCompareObjects = unsafe extern "system" fn(HANDLE, HANDLE) -> i32;

fn nt_compare_objects() -> Option<FnNtCompareObjects> {
    static F: std::sync::OnceLock<Option<FnNtCompareObjects>> = std::sync::OnceLock::new();
    *F.get_or_init(|| {
        // SAFETY: ntdll export resolved by name; transmuted to its documented
        // ABI (HANDLE, HANDLE) -> NTSTATUS. Absent before Win10 1607 → None.
        unsafe {
            crate::hooks::ntdll_export(b"NtCompareObjects\0")
                .map(|a| std::mem::transmute::<*const (), FnNtCompareObjects>(a))
        }
    })
}

/// Granted access mask of a handle (ObjectBasicInformation), for diagnostics.
///
/// # Safety
/// `h` is passed to the kernel, which validates it.
pub unsafe fn granted_access(h: HANDLE) -> Option<u32> {
    type FnNtQueryObject =
        unsafe extern "system" fn(HANDLE, u32, *mut u8, u32, *mut u32) -> i32;
    // SAFETY: ntdll export resolved by name, documented ABI.
    let f: FnNtQueryObject = unsafe {
        std::mem::transmute(crate::hooks::ntdll_export(b"NtQueryObject\0")?)
    };
    let mut buf = [0u8; 56]; // exact size required, else INFO_LENGTH_MISMATCH
    // SAFETY: buf outlives the call; class 0 = ObjectBasicInformation (56 bytes).
    let st = unsafe { f(h, 0, buf.as_mut_ptr(), buf.len() as u32, std::ptr::null_mut()) };
    (st >= 0).then(|| u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]))
}

/// Close entries whose process has exited (lazy pruning; no waiter thread).
fn prune(v: &mut Vec<(u32, usize)>) {
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::synchapi::WaitForSingleObject;
    v.retain(|&(_, h)| {
        // SAFETY: h is our own duplicate, open until closed here.
        let exited = unsafe { WaitForSingleObject(h as HANDLE, 0) } == 0;
        if exited {
            unsafe { CloseHandle(h as HANDLE) };
        }
        !exited
    });
}

/// Keep a duplicate of the freshly spawned child's handle.
///
/// # Safety
/// `proc_h` must be a valid process handle owned by this process.
pub unsafe fn remember(pid: u32, proc_h: HANDLE) {
    use winapi::um::handleapi::DuplicateHandle;
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::winnt::{PROCESS_QUERY_LIMITED_INFORMATION, SYNCHRONIZE};
    let mut dup: HANDLE = std::ptr::null_mut();
    // SAFETY: same-process duplication of a valid handle to a subset right.
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(), proc_h, GetCurrentProcess(), &mut dup,
            SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, 0,
        )
    };
    if ok == 0 || dup.is_null() {
        return;
    }
    let mut v = HANDLES.lock().unwrap_or_else(|p| p.into_inner());
    prune(&mut v);
    v.push((pid, dup as usize));
}

/// PID of the remembered live child that `h` refers to, if any.
///
/// # Safety
/// `h` must be a handle value of this process (validity is checked by the kernel).
pub unsafe fn child_pid_of(h: HANDLE) -> Option<u32> {
    let cmp = nt_compare_objects()?;
    let mut v = HANDLES.lock().unwrap_or_else(|p| p.into_inner());
    prune(&mut v);
    v.iter()
        // SAFETY: both handles are passed to the kernel, which validates them.
        .find(|&&(_, own)| unsafe { cmp(h, own as HANDLE) } == 0)
        .map(|&(pid, _)| pid)
}

/// Exit code of the remembered child `h` refers to (259 = still running).
///
/// # Safety
/// `h` is passed to the kernel, which validates it.
pub unsafe fn exit_code_of(h: HANDLE) -> Option<u32> {
    let cmp = nt_compare_objects()?;
    let v = HANDLES.lock().unwrap_or_else(|p| p.into_inner());
    // SAFETY: both handles validated by the kernel.
    let &(_, own) = v.iter().find(|&&(_, own)| unsafe { cmp(h, own as HANDLE) } == 0)?;
    let mut code = 0u32;
    // SAFETY: our own duplicate with QUERY_LIMITED rights.
    (unsafe { winapi::um::processthreadsapi::GetExitCodeProcess(own as HANDLE, &mut code) } != 0)
        .then_some(code)
}

/// Drop the duplicate for `pid` (child untracked).
pub fn forget(pid: u32) {
    use winapi::um::handleapi::CloseHandle;
    let mut v = HANDLES.lock().unwrap_or_else(|p| p.into_inner());
    v.retain(|&(p, h)| {
        if p == pid {
            // SAFETY: our own duplicate.
            unsafe { CloseHandle(h as HANDLE) };
        }
        p != pid
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A handle without query rights still resolves to the remembered child.
    #[test]
    fn resolves_handle_without_query_rights() {
        use std::os::windows::io::AsRawHandle;
        use winapi::um::handleapi::{CloseHandle, DuplicateHandle};
        use winapi::um::processthreadsapi::GetCurrentProcess;
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/c", "ping -n 3 127.0.0.1 >nul"])
            .spawn()
            .unwrap();
        let full = child.as_raw_handle() as HANDLE;
        unsafe { remember(child.id(), full) };
        // PROCESS_SET_QUOTA | PROCESS_TERMINATE: what AssignProcessToJobObject needs.
        let mut weak: HANDLE = std::ptr::null_mut();
        unsafe {
            DuplicateHandle(GetCurrentProcess(), full, GetCurrentProcess(), &mut weak, 0x0101, 0, 0)
        };
        assert!(!weak.is_null());
        assert_eq!(unsafe { winapi::um::processthreadsapi::GetProcessId(weak) }, 0);
        assert_eq!(unsafe { child_pid_of(weak) }, Some(child.id()));
        forget(child.id());
        assert_eq!(unsafe { child_pid_of(weak) }, None);
        unsafe { CloseHandle(weak) };
        let _ = child.kill();
        let _ = child.wait();
    }
}
