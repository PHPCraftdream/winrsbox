// Tries NtUnmapViewOfSection on a foreign (non-self) process.
// Uses PROCESS_VM_READ only (not VM_OPERATION) to bypass proc_guard's
// OpenProcess deny, so the payload reaches our memory_guard cross-proc hook.
// Without hook: unmap reaches kernel (may fail with STATUS_NOT_MAPPED_VIEW).
// With hook: NtUnmapViewOfSection denied → STATUS_ACCESS_DENIED → exit 5.

use winapi::shared::minwindef::FALSE;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::PROCESS_VM_READ;
use winapi::um::tlhelp32::*;
use winapi::um::handleapi::{INVALID_HANDLE_VALUE, CloseHandle};

fn find_pid(name: &str) -> Option<u32> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE { return None; }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut e) == 0 { CloseHandle(snap); return None; }
        loop {
            let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
            let exe = String::from_utf16_lossy(&e.szExeFile[..len]).to_lowercase();
            if exe == name.to_lowercase() { CloseHandle(snap); return Some(e.th32ProcessID); }
            if Process32NextW(snap, &mut e) == 0 { CloseHandle(snap); return None; }
        }
    }
}

fn main() {
    eprintln!("[escape_unmap_foreign] starting");
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    for _ in 0..3 { unsafe { winapi::um::synchapi::SleepEx(200, 1); } }

    // Target explorer.exe (always present on desktop session)
    let pid = match find_pid("explorer.exe") {
        Some(p) => p,
        None => { eprintln!("[escape_unmap_foreign] explorer.exe not found, skipping"); std::process::exit(7); }
    };
    eprintln!("[escape_unmap_foreign] target pid={pid}");

    unsafe {
        // PROCESS_VM_READ only — bypasses proc_guard (not in DANGEROUS_ACCESS mask)
        // so our memory_guard NtUnmapViewOfSection hook is actually exercised.
        let h = OpenProcess(PROCESS_VM_READ, FALSE, pid);
        if h.is_null() {
            eprintln!("[escape_unmap_foreign] blocked at OpenProcess — unexpected (VM_READ should pass proc_guard)");
            std::process::exit(5);
        }

        type FnNtUnmapView = unsafe extern "system" fn(*mut std::ffi::c_void, *mut std::ffi::c_void) -> i32;
        let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let h_ntdll = winapi::um::libloaderapi::GetModuleHandleW(ntdll_w.as_ptr());
        let addr = winapi::um::libloaderapi::GetProcAddress(h_ntdll, b"NtUnmapViewOfSection\0".as_ptr() as *const i8);
        if addr.is_null() {
            eprintln!("[escape_unmap_foreign] NtUnmapViewOfSection not exported (unlikely)");
            CloseHandle(h);
            std::process::exit(8);
        }
        let nt_unmap: FnNtUnmapView = std::mem::transmute(addr);

        // Use a plausible base address (ntdll base in foreign process)
        let fake_base = h_ntdll as *mut std::ffi::c_void;
        let status = nt_unmap(h as *mut _, fake_base);
        eprintln!("[escape_unmap_foreign] NtUnmapViewOfSection status=0x{:x}", status as u32);
        CloseHandle(h);

        if status == 0xC0000022u32 as i32 {
            eprintln!("[escape_unmap_foreign] blocked: STATUS_ACCESS_DENIED from our hook");
            std::process::exit(5);
        }
        // STATUS_NOT_MAPPED_VIEW (0xC0000019) means kernel handled it normally
        // — our hook didn't fire. That's a FAILURE.
        eprintln!("[escape_unmap_foreign] FOUND: hook didn't fire, foreign unmap reached kernel");
        std::process::exit(0);
    }
}
