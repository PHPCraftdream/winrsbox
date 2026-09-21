// Named-pipe impersonation escape test.
//
// Creates a named pipe, connects a client thread, then attempts
// ImpersonateNamedPipeClient — which internally issues
// NtFsControlFile(FSCTL_PIPE_IMPERSONATE).  With the hook active this
// returns ACCESS_DENIED → exit 5.  Without the hook, impersonation
// succeeds → exit 0 (escape vector).

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use winapi::shared::minwindef::FALSE;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::CreateFileW;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::namedpipeapi::{ConnectNamedPipe, CreateNamedPipeW, ImpersonateNamedPipeClient};
use winapi::um::winbase::{PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, PIPE_READMODE_BYTE, PIPE_WAIT};

fn main() {
    eprintln!("[escape_pipe_impersonate] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 {
        unsafe {
            winapi::um::synchapi::SleepEx(200, 1);
        }
    }

    let pid = std::process::id();
    let pipe_name = format!(r"\\.\pipe\winrsbox-test-impersonate-{pid}");
    let pipe_w: Vec<u16> = OsStr::new(&pipe_name)
        .encode_wide()
        .chain(Some(0))
        .collect();

    unsafe {
        let pipe = CreateNamedPipeW(
            pipe_w.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            4096,
            4096,
            0,
            null_mut(),
        );
        if pipe == INVALID_HANDLE_VALUE {
            eprintln!(
                "[escape_pipe_impersonate] CreateNamedPipe failed err={}",
                GetLastError()
            );
            std::process::exit(7);
        }

        // Client thread — connects to the pipe from the same process.
        // The hook blocks FSCTL_PIPE_IMPERSONATE regardless of who connected.
        let pipe_name_clone = pipe_name.clone();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let w: Vec<u16> = OsStr::new(&pipe_name_clone)
                .encode_wide()
                .chain(Some(0))
                .collect();
            let h = CreateFileW(
                w.as_ptr(),
                0x80000000 /*GENERIC_READ*/ | 0x40000000 /*GENERIC_WRITE*/,
                0,
                null_mut(),
                3, /*OPEN_EXISTING*/
                0,
                null_mut(),
            );
            if h != INVALID_HANDLE_VALUE {
                CloseHandle(h);
            }
        });

        let ok = ConnectNamedPipe(pipe, null_mut());
        if ok == 0 {
            let err = GetLastError();
            // ERROR_PIPE_CONNECTED (535) is fine — client already connected.
            if err != 535 {
                eprintln!(
                    "[escape_pipe_impersonate] ConnectNamedPipe failed err={}",
                    err
                );
                let _ = handle.join();
                CloseHandle(pipe);
                std::process::exit(8);
            }
        }

        let imp_ok = ImpersonateNamedPipeClient(pipe);
        let _ = handle.join();

        if imp_ok == 0 {
            let err = GetLastError();
            eprintln!(
                "[escape_pipe_impersonate] blocked: ImpersonateNamedPipeClient err={}",
                err
            );
            CloseHandle(pipe);
            std::process::exit(5);
        }

        eprintln!("[escape_pipe_impersonate] FOUND: impersonation succeeded — escape vector!");
        let _ = winapi::um::securitybaseapi::RevertToSelf();
        CloseHandle(pipe);
        std::process::exit(0);
    }
}
