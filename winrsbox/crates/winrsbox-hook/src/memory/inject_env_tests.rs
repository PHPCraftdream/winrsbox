// Regression: patch_child_env_pairs must reach a real child. The old
// `Length == 0x400` guard skipped every child (Length spans the packed
// strings too), so a child spawned with an explicit, scrubbed environment
// (codex MCP servers) never got FS_SANDBOX_SECTION and failed closed.

use super::*;
use std::os::windows::ffi::OsStrExt;
use winapi::um::processthreadsapi::{
    CreateProcessW, GetExitCodeProcess, ResumeThread, PROCESS_INFORMATION, STARTUPINFOW,
};
use winapi::um::winbase::{CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT};

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

#[test]
fn injected_var_reaches_child_with_explicit_env() {
    let sysroot = std::env::var("SystemRoot").unwrap();
    let mut env: Vec<u16> = format!("SystemRoot={sysroot}").encode_utf16().collect();
    env.extend([0, 0]);
    let mut cmd = wide(r#"C:\Windows\System32\cmd.exe /c "if defined WRSB_T (exit 42) else (exit 1)""#);
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: all pointers are valid locals for the call.
    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(), cmd.as_mut_ptr(), std::ptr::null_mut(), std::ptr::null_mut(), 0,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            env.as_mut_ptr() as *mut _, std::ptr::null(), &mut si, &mut pi,
        )
    };
    assert_ne!(ok, 0, "CreateProcessW failed");
    let patched = patch_child_env_pairs(pi.hProcess, &[("WRSB_T", "1")]);
    // SAFETY: valid thread/process handles from CreateProcessW.
    let code = unsafe {
        ResumeThread(pi.hThread);
        winapi::um::synchapi::WaitForSingleObject(pi.hProcess, 15_000);
        let mut c = 0u32;
        GetExitCodeProcess(pi.hProcess, &mut c);
        winapi::um::handleapi::CloseHandle(pi.hThread);
        winapi::um::handleapi::CloseHandle(pi.hProcess);
        c
    };
    patched.expect("patch_child_env_pairs");
    assert_eq!(code, 42, "injected variable not visible in the child");
}
