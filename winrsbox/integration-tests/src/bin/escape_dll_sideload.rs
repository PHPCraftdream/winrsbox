// Escape payload: verify PROCESS_MITIGATION_IMAGE_LOAD_POLICY is applied.
// Queries GetProcessMitigationPolicy for ProcessImageLoadPolicy (policy 10).
// If PreferSystem32Images=1 and NoRemoteImages=1 → exit 5 (defense active).
// If mitigations missing → exit 0 (DLL sideloading escape possible).

fn main() {
    eprintln!("[escape_dll_sideload] starting");
    // Touch a known system DLL so the loader has resolved kernel32 before we query.
    let _ = std::fs::metadata(r"C:\Windows\System32\kernel32.dll");
    // Brief sleep to let hook.dll apply mitigations via SetProcessMitigationPolicy.
    for _ in 0..3 {
        unsafe { winapi::um::synchapi::SleepEx(200, 1); }
    }

    unsafe {
        // PROCESS_MITIGATION_IMAGE_LOAD_POLICY bit layout (from msdocs):
        //   DWORD NoRemoteImages : 1;           // bit 0
        //   DWORD NoLowMandatoryLabelImages : 1; // bit 1
        //   DWORD PreferSystem32Images : 1;     // bit 2
        //   DWORD ReservedFlags : 29;
        let mut flags: u32 = 0;
        let ok = winapi::um::processthreadsapi::GetProcessMitigationPolicy(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            10i32 as winapi::um::winnt::PROCESS_MITIGATION_POLICY, // ProcessImageLoadPolicy
            &mut flags as *mut u32 as *mut _,
            std::mem::size_of::<u32>(),
        );
        if ok == 0 {
            eprintln!("[escape_dll_sideload] GetProcessMitigationPolicy failed (not available on this OS?)");
            std::process::exit(2);
        }

        let no_remote = (flags >> 0) & 1;
        let no_low = (flags >> 1) & 1;
        let prefer_sys32 = (flags >> 2) & 1;

        eprintln!(
            "[escape_dll_sideload] NoRemote={} NoLow={} PreferSystem32={} (raw=0x{:x})",
            no_remote, no_low, prefer_sys32, flags,
        );

        if prefer_sys32 == 1 && no_remote == 1 {
            eprintln!("[escape_dll_sideload] mitigations active — DLL hijack defense ON");
            std::process::exit(5);
        }
        eprintln!("[escape_dll_sideload] FAIL: mitigations not applied — DLL hijack possible");
        std::process::exit(0);
    }
}
