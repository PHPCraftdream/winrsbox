use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
use windows::Win32::Security::WinTrust::*;
use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_IMAGE};
use windows::Win32::System::ProcessStatus::GetMappedFileNameW;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

struct Process(HANDLE);
impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: this guard owns the handle returned by OpenProcess.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Resolve the image from the authenticated pipe client's address space.
/// Verification runs in the broker, outside the guest's loader lock.
pub fn verify_microsoft_mapping(pid: u32, base: u64) -> bool {
    let Ok(address) = usize::try_from(base) else {
        return false;
    };
    if address == 0 {
        return false;
    }
    // SAFETY: OpenProcess validates the PID and requested rights.
    let Ok(handle) =
        (unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) })
    else {
        return false;
    };
    let process = Process(handle);
    let mut info = MEMORY_BASIC_INFORMATION::default();
    // SAFETY: the kernel probes the remote address; info is writable.
    let queried = unsafe {
        VirtualQueryEx(
            process.0,
            Some(address as *const _),
            &mut info,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if queried == 0 || info.Type != MEM_IMAGE || info.AllocationBase as usize != address {
        return false;
    }
    let mut name = vec![0u16; 32768];
    // SAFETY: the process handle is live and name is a writable UTF-16 buffer.
    let len = unsafe { GetMappedFileNameW(process.0, address as *const _, &mut name) } as usize;
    if len == 0 || len >= name.len() {
        return false;
    }
    let Ok(nt_path) = String::from_utf16(&name[..len]) else {
        return false;
    };
    if !nt_path.starts_with(r"\Device\") {
        return false;
    }
    let path = std::path::PathBuf::from(format!(r"\\?\GLOBALROOT{nt_path}"));
    verify_image_file(&path)
}

fn verify_image_file(path: &Path) -> bool {
    // Deny writes/replacement until hashing and verification finish.
    let Ok(file) = OpenOptions::new().read(true).share_mode(1).open(path) else {
        return false;
    };
    let Ok(key) = policy::pe_cache::file_key(path) else {
        return false;
    };
    static CACHE: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(result) = cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .copied()
    {
        return result;
    }
    let trusted = verify_open_file(path, &file);
    let mut results = cache.lock().unwrap_or_else(|e| e.into_inner());
    if results.len() >= 128 {
        results.clear();
    }
    results.insert(key, trusted);
    trusted
}

struct TrustState {
    action: GUID,
    data: WINTRUST_DATA,
}
impl Drop for TrustState {
    fn drop(&mut self) {
        self.data.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: state and its file-info backing remain live until this drop.
        unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut self.action,
                &mut self.data as *mut _ as *mut _,
            );
        }
    }
}

fn verify_open_file(path: &Path, file: &File) -> bool {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        hFile: HANDLE(file.as_raw_handle()),
        ..Default::default()
    };
    let mut state = TrustState {
        action: GUID::from_u128(0x00aac56b_cd44_11d0_8cc2_00c04fc295ee),
        data: WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 {
                pFile: &mut file_info,
            },
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE,
            ..Default::default()
        },
    };
    // SAFETY: file_info, path and file handle outlive verification and state cleanup.
    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut state.action,
            &mut state.data as *mut _ as *mut _,
        )
    };
    if status != 0 {
        return false;
    }
    // SAFETY: successful verification owns live provider state until TrustState drops.
    unsafe {
        let provider = WTHelperProvDataFromStateData(state.data.hWVTStateData);
        if provider.is_null() {
            return false;
        }
        let signer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
        if signer.is_null() {
            return false;
        }
        let signer = &*signer;
        if signer.dwError != 0 || signer.csCertChain == 0 || signer.pasCertChain.is_null() {
            return false;
        }
        // The verified signer's leaf certificate, not an arbitrary certificate in the PKCS7 store.
        let cert = (*signer.pasCertChain).pCert;
        if cert.is_null() {
            return false;
        }
        let len = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None) as usize;
        if !(2..=4096).contains(&len) {
            return false;
        }
        let mut name = vec![0u16; len];
        if CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut name),
        ) as usize
            != len
        {
            return false;
        }
        matches!(
            String::from_utf16_lossy(&name[..len - 1]).as_str(),
            "Microsoft Corporation" | "Microsoft Windows" | "Microsoft Windows Publisher"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_image_and_invalid_mapping_are_not_trusted() {
        assert!(!verify_image_file(&std::env::current_exe().unwrap()));
        // SAFETY: GetCurrentProcessId has no preconditions.
        let pid = unsafe { windows::Win32::System::Threading::GetCurrentProcessId() };
        assert!(!verify_microsoft_mapping(pid, 0));
        assert!(!verify_microsoft_mapping(pid, 1));
    }

    #[test]
    fn microsoft_compiler_signature_rejects_modified_content() {
        let root = std::env::var_os("SystemRoot").expect("Windows root");
        let source =
            std::path::PathBuf::from(root).join("Microsoft.NET/Framework64/v4.0.30319/csc.exe");
        assert!(
            verify_image_file(&source),
            "Framework compiler must have a verified Microsoft signature"
        );
        let fixture = tempfile::tempdir().unwrap();
        let modified = fixture.path().join("csc.exe");
        let mut bytes = std::fs::read(source).unwrap();
        bytes[1024] ^= 1;
        std::fs::write(&modified, bytes).unwrap();
        assert!(
            !verify_image_file(&modified),
            "changed content must invalidate trust and its cache key"
        );
    }

    #[test]
    fn loaded_microsoft_compiler_is_verified_by_kernel_mapping() {
        use windows::Win32::Foundation::{FreeLibrary, HMODULE};
        use windows::Win32::System::LibraryLoader::{LoadLibraryExW, DONT_RESOLVE_DLL_REFERENCES};
        struct Module(HMODULE);
        impl Drop for Module {
            fn drop(&mut self) {
                // SAFETY: owns the module returned by LoadLibraryExW.
                unsafe {
                    let _ = FreeLibrary(self.0);
                }
            }
        }
        let root = std::env::var_os("SystemRoot").unwrap();
        let path =
            std::path::PathBuf::from(root).join("Microsoft.NET/Framework64/v4.0.30319/csc.exe");
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: valid path; DONT_RESOLVE avoids executing compiler initialization.
        let module = Module(
            unsafe { LoadLibraryExW(PCWSTR(wide.as_ptr()), None, DONT_RESOLVE_DLL_REFERENCES) }
                .unwrap(),
        );
        // SAFETY: GetCurrentProcessId has no preconditions.
        let pid = unsafe { windows::Win32::System::Threading::GetCurrentProcessId() };
        assert!(verify_microsoft_mapping(pid, module.0 .0 as u64));
    }
}
