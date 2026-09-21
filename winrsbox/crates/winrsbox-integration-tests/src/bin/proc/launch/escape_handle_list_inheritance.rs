// Tries to spawn child with PROC_THREAD_ATTRIBUTE_HANDLE_LIST containing self handle.
// Without hook: child inherits the handle, can use it.
// With hook: NtCreateUserProcess denied -> CreateProcessW returns 0 -> exit 5.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::{
    CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
    UpdateProcThreadAttribute, GetCurrentProcess, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROCESS_INFORMATION,
};
use winapi::um::winbase::{EXTENDED_STARTUPINFO_PRESENT, STARTUPINFOEXW};

const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x00020002;

fn main() {
    eprintln!("[escape_handle_list_inheritance] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 {
        unsafe { winapi::um::synchapi::SleepEx(200, 1); }
    }

    unsafe {
        let mut handles: [winapi::shared::ntdef::HANDLE; 1] = [GetCurrentProcess()];

        let mut size: usize = 0;
        InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size);
        let mut buf = vec![0u8; size];
        let attr_list = buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
        if InitializeProcThreadAttributeList(attr_list, 1, 0, &mut size) == 0 {
            eprintln!("InitializeProcThreadAttributeList failed");
            std::process::exit(8);
        }
        if UpdateProcThreadAttribute(
            attr_list, 0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            handles.as_mut_ptr() as *mut _,
            std::mem::size_of::<winapi::shared::ntdef::HANDLE>(),
            null_mut(), null_mut(),
        ) == 0 {
            eprintln!("UpdateProcThreadAttribute failed");
            DeleteProcThreadAttributeList(attr_list);
            std::process::exit(8);
        }

        let app: Vec<u16> = OsStr::new(r"C:\Windows\System32\cmd.exe")
            .encode_wide().chain(Some(0)).collect();
        let mut cmd: Vec<u16> = OsStr::new(r"cmd.exe /c exit 0")
            .encode_wide().chain(Some(0)).collect();

        let mut si: STARTUPINFOEXW = std::mem::zeroed();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = attr_list;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        let ok = CreateProcessW(
            app.as_ptr(), cmd.as_mut_ptr(),
            null_mut(), null_mut(),
            1, // bInheritHandles = TRUE
            EXTENDED_STARTUPINFO_PRESENT,
            null_mut(), null_mut(),
            &mut si as *mut _ as *mut _, &mut pi,
        );
        DeleteProcThreadAttributeList(attr_list);

        if ok == 0 {
            let err = GetLastError();
            eprintln!("[escape_handle_list_inheritance] blocked: CreateProcessW err={}", err);
            std::process::exit(5);
        }
        eprintln!("[escape_handle_list_inheritance] FOUND: spawned with explicit HANDLE_LIST - escape!");
        winapi::um::processthreadsapi::TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        std::process::exit(0);
    }
}
