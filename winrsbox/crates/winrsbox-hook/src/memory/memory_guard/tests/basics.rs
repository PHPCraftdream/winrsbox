use super::*;

#[test]
fn is_executable_page_readwrite() {
    assert!(!is_executable(0x04)); // PAGE_READWRITE
}

#[test]
fn is_executable_page_execute() {
    assert!(is_executable(PAGE_EXECUTE));
}

#[test]
fn is_executable_page_execute_read() {
    assert!(is_executable(PAGE_EXECUTE_READ));
}

#[test]
fn is_executable_page_execute_readwrite() {
    assert!(is_executable(PAGE_EXECUTE_READWRITE));
}

#[test]
fn is_executable_page_execute_writecopy() {
    assert!(is_executable(PAGE_EXECUTE_WRITECOPY));
}

#[test]
fn is_executable_page_noaccess() {
    assert!(!is_executable(0x01)); // PAGE_NOACCESS
}

#[test]
fn is_executable_page_readonly() {
    assert!(!is_executable(0x02)); // PAGE_READONLY
}

#[test]
fn is_executable_combined_guard() {
    // PAGE_EXECUTE_READ | PAGE_GUARD (0x100)
    assert!(is_executable(0x20 | 0x100));
}

#[test]
fn is_executable_zero() {
    assert!(!is_executable(0));
}

#[test]
fn protect_name_covers_all_exec() {
    assert_eq!(protect_name(PAGE_EXECUTE_READWRITE), "PAGE_EXECUTE_READWRITE");
    assert_eq!(protect_name(PAGE_EXECUTE_WRITECOPY), "PAGE_EXECUTE_WRITECOPY");
    assert_eq!(protect_name(PAGE_EXECUTE_READ), "PAGE_EXECUTE_READ");
    assert_eq!(protect_name(PAGE_EXECUTE), "PAGE_EXECUTE");
    assert_eq!(protect_name(0x04), "non-execute");
}

#[test]
fn is_address_in_module_null() {
    assert!(!is_address_in_module(std::ptr::null()));
}

#[test]
fn is_address_in_module_ntdll() {
    // GetModuleHandleW("ntdll.dll") gives us an address inside ntdll.
    // SAFETY: ntdll.dll is always loaded.
    let hmod = unsafe {
        let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        winapi::um::libloaderapi::GetModuleHandleW(name.as_ptr())
    };
    assert!(!hmod.is_null());
    // The module handle IS the base address — it's inside the module.
    assert!(is_address_in_module(hmod as *const c_void));
}

#[test]
fn is_address_in_module_heap_allocation() {
    // Heap allocation is NOT in any module.
    let v = vec![0u8; 64];
    assert!(!is_address_in_module(v.as_ptr() as *const c_void));
}

#[test]
fn module_path_for_ntdll() {
    let hmod = unsafe {
        let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        winapi::um::libloaderapi::GetModuleHandleW(name.as_ptr())
    };
    let path = module_path_for_address(hmod as *const c_void);
    assert!(path.is_some());
    let p = path.unwrap().to_lowercase();
    assert!(p.contains("ntdll.dll"), "got: {p}");
}

#[test]
fn module_path_for_heap_is_none() {
    let v = vec![0u8; 64];
    assert!(module_path_for_address(v.as_ptr() as *const c_void).is_none());
}

#[test]
fn nt_current_process_check() {
    assert!(is_current_process(-1isize as HANDLE));
    assert!(!is_current_process(std::ptr::null_mut()));
    assert!(!is_current_process(42usize as HANDLE));
}

#[test]
fn critical_dll_detection() {
    assert!(is_critical_dll("ntdll.dll"));
    assert!(is_critical_dll("kernel32.dll"));
    assert!(is_critical_dll("kernelbase.dll"));
    assert!(is_critical_dll("hook.dll"));
    assert!(!is_critical_dll("user32.dll"));
    assert!(!is_critical_dll("evil.dll"));
    assert!(!is_critical_dll(""));
}

#[test]
fn extract_basename_lower_works() {
    assert_eq!(extract_basename_lower(r"C:\Windows\System32\ntdll.dll"), "ntdll.dll");
    assert_eq!(extract_basename_lower(r"\Device\HarddiskVolume3\Windows\System32\kernel32.dll"), "kernel32.dll");
    assert_eq!(extract_basename_lower("hook.dll"), "hook.dll");
    assert_eq!(extract_basename_lower(""), "");
}

#[test]
fn is_image_mapping_for_ntdll_base() {
    // ntdll's base should be MEM_IMAGE
    let hmod = unsafe {
        let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        winapi::um::libloaderapi::GetModuleHandleW(name.as_ptr())
    };
    assert!(!hmod.is_null());
    assert!(is_image_mapping(hmod as *const c_void));
}

#[test]
fn is_image_mapping_for_heap_is_false() {
    let v = vec![0u8; 64];
    assert!(!is_image_mapping(v.as_ptr() as *const c_void));
}

#[test]
fn is_system_dll_path_under_matches_whole_components() {
    // Previously-trusted layouts stay trusted under an explicit canonical
    // root; matching is whole-component, never substring.
    let root = r"\Device\HarddiskVolume3\Windows";
    assert!(is_system_dll_path_under(r"\Device\HarddiskVolume3\Windows\System32\user32.dll", root));
    assert!(is_system_dll_path_under(r"\Device\HarddiskVolume3\Windows\SysWOW64\kernel32.dll", root));
    assert!(is_system_dll_path_under(r"\device\harddiskvolume3\windows\system32\ntdll.dll", root));
    assert!(is_system_dll_path_under(
        r"\Device\HarddiskVolume3\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll",
        root
    ));
    assert!(is_system_dll_path_under(
        r"\Device\HarddiskVolume3\Windows\assembly\NativeImages_v4.0.30319_64\mscorlib\abc\mscorlib.ni.dll",
        root
    ));
    // A different volume's Windows tree is not this root.
    assert!(!is_system_dll_path_under(r"\Device\HarddiskVolume9\Windows\System32\user32.dll", root));
    // Component boundary: System32X / System32.evildir must not match.
    assert!(!is_system_dll_path_under(r"\Device\HarddiskVolume3\Windows\System32X\evil.dll", root));
    assert!(!is_system_dll_path_under(r"\Device\HarddiskVolume3\Windows\System32.evildir\evil.dll", root));
    // Nested look-alike: the trusted component must sit directly under
    // the root, not deeper in the tree.
    assert!(!is_system_dll_path_under(r"\Device\HarddiskVolume3\Windows\spoof\system32\evil.dll", root));
}

#[test]
fn is_system_dll_path_rejects_spoofed_substring() {
    // Regression (audit 2026-09-19, Medium): the old implementation
    // trusted any path CONTAINING `\windows\system32\`. Every one of
    // these must be untrusted.
    assert!(!is_system_dll_path(r"\Device\HarddiskVolume9\tmp\windows\system32\evil.dll"));
    assert!(!is_system_dll_path(r"C:\tmp\windows\system32\evil.dll"));
    assert!(!is_system_dll_path(
        r"\Device\HarddiskVolume3\Users\x\AppData\Local\Temp\windows\system32\evil.dll"
    ));
    // Pre-existing negatives keep failing closed.
    assert!(!is_system_dll_path(r"\Device\HarddiskVolume3\Users\x\AppData\evil.dll"));
    assert!(!is_system_dll_path(r"\Device\HarddiskVolume3\Program Files\app\plugin.dll"));
    assert!(!is_system_dll_path(""));
}

#[test]
fn is_system_dll_path_anchored_fallback() {
    // Fallback (root resolution unavailable): component-anchored at a
    // volume root — still never a substring match.
    assert!(is_system_dll_path_anchored(r"\Device\HarddiskVolume3\Windows\System32\ntdll.dll"));
    assert!(is_system_dll_path_anchored(r"C:\Windows\SysWOW64\kernel32.dll"));
    assert!(!is_system_dll_path_anchored(r"C:\tmp\windows\system32\evil.dll"));
    assert!(!is_system_dll_path_anchored(r"\Device\HarddiskVolume3\tmp\windows\system32\evil.dll"));
    assert!(!is_system_dll_path_anchored(r"\Device\HarddiskVolume3\Windows\System32X\evil.dll"));
    assert!(!is_system_dll_path_anchored(""));
}

#[test]
fn is_system_dll_path_real_root_resolution() {
    // Production path: prefixes resolved from the loader's own ntdll
    // mapping. The real System32 must be trusted; the same tail planted
    // one component deeper must not.
    match trusted_windows_root_nt() {
        Some(root) => {
            assert!(is_system_dll_path(&format!("{}\\system32\\user32.dll", root)));
            assert!(is_system_dll_path(&format!("{}\\syswow64\\kernel32.dll", root)));
            assert!(!is_system_dll_path(&format!("{}\\spoof\\system32\\user32.dll", root)));
        }
        None => {
            // Root unresolved in this environment: the fallback must
            // still reject the substring spoof.
            assert!(!is_system_dll_path(r"C:\tmp\windows\system32\evil.dll"));
        }
    }
}

#[test]
fn get_mapped_file_basename_for_ntdll() {
    let hmod = unsafe {
        let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        winapi::um::libloaderapi::GetModuleHandleW(name.as_ptr())
    };
    let basename = get_mapped_file_basename(hmod as *const c_void);
    assert!(basename.is_some());
    assert_eq!(basename.unwrap(), "ntdll.dll");
}
