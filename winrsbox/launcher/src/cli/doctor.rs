use anyhow::Result;
use std::path::Path;

pub fn run() -> Result<()> {
    println!("winrsbox doctor");
    println!("===============");

    check_windows_version();
    check_wfp();
    check_hook_dll();

    println!();
    Ok(())
}

fn check_windows_version() {
    #[repr(C)]
    struct OsVer { size: u32, major: u32, minor: u32, build: u32, plat: u32, _sp: [u16; 128], _r: [u8; 8] }
    extern "system" { fn RtlGetVersion(i: *mut OsVer) -> i32; }
    let mut v: OsVer = unsafe { std::mem::zeroed() };
    v.size = std::mem::size_of::<OsVer>() as u32;
    unsafe { RtlGetVersion(&mut v) };
    let ok = v.major >= 10 && v.build >= 17134;
    let icon = if ok { "PASS" } else { "FAIL" };
    println!("  [{icon}] Windows {}.{}.{} (>= 10.0.17134 required)", v.major, v.minor, v.build);
}

fn check_wfp() {
    use windows::core::PCWSTR;
    use windows::Win32::System::LibraryLoader::LoadLibraryW;
    let name: Vec<u16> = "fwpuclnt.dll\0".encode_utf16().collect();
    let ok = unsafe { LoadLibraryW(PCWSTR(name.as_ptr())) }.is_ok();
    let icon = if ok { "PASS" } else { "FAIL" };
    println!("  [{icon}] WFP available (fwpuclnt.dll)");
}

fn check_hook_dll() {
    let exe = std::env::current_exe().unwrap_or_default();
    let dll = exe.parent().unwrap_or(Path::new(".")).join("hook.dll");
    let ok = dll.exists();
    let icon = if ok { "PASS" } else { "FAIL" };
    println!("  [{icon}] hook.dll {}", if ok { "found" } else { "NOT FOUND" });
}
