// Trust verification via Windows Authenticode signatures.
//
// Uses WinVerifyTrust to check if an executable is signed by a publisher
// whose cert chain roots in Windows' Trusted Root CA store.
// NO hardcoded publisher list — Windows decides what is trusted.

use std::collections::HashMap;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustLevel {
    /// Signed by publisher whose cert chains to a MS-trusted root.
    Signed { publisher: String },
    /// Signed but cert chain doesn't reach a trusted root (self-signed, dev cert).
    SignedUntrustedRoot,
    /// No Authenticode signature.
    Unsigned,
    /// Verification failed for other reason (file not found, corrupt PE, etc).
    Error(String),
}

impl TrustLevel {
    pub fn is_trusted(&self) -> bool {
        matches!(self, TrustLevel::Signed { .. })
    }
}

// ---------------------------------------------------------------------------
// WinVerifyTrust wrapper
// ---------------------------------------------------------------------------

/// Verify Authenticode signature of an executable using WinVerifyTrust.
/// Returns TrustLevel based on Windows' own certificate validation.
pub fn verify_signature(exe_path: &Path) -> TrustLevel {
    use windows::Win32::Security::WinTrust::*;
    use windows::Win32::Foundation::HWND;
    use windows::core::GUID;

    let path_wide: Vec<u16> = exe_path.as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: windows::core::PCWSTR(path_wide.as_ptr()),
        ..Default::default()
    };

    let mut wintrust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        ..Default::default()
    };

    // WINTRUST_ACTION_GENERIC_VERIFY_V2
    let mut action_id = GUID::from_values(
        0x00AAC56B, 0xCD44, 0x11d0, [0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE],
    );

    // SAFETY: all structs are valid; path_wide is null-terminated and outlives the call.
    let status = unsafe {
        WinVerifyTrust(
            HWND::default(), // no UI
            &mut action_id,
            &mut wintrust_data as *mut _ as *mut _,
        )
    };

    // Close state
    wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(HWND::default(), &mut action_id, &mut wintrust_data as *mut _ as *mut _);
    }

    match status {
        0 => {
            // Signature is valid + trusted. Extract publisher.
            let publisher = extract_publisher(exe_path).unwrap_or_else(|| "<unknown>".into());
            TrustLevel::Signed { publisher }
        }
        x if x == 0x800B0100_u32 as i32 => {
            // TRUST_E_NOSIGNATURE — unsigned
            TrustLevel::Unsigned
        }
        x if x == 0x800B0109_u32 as i32 => {
            // CERT_E_UNTRUSTEDROOT
            TrustLevel::SignedUntrustedRoot
        }
        other => {
            TrustLevel::Error(format!("WinVerifyTrust returned 0x{other:08x}"))
        }
    }
}

/// Extract publisher CN from Authenticode signature via CryptQueryObject.
fn extract_publisher(exe_path: &Path) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Security::Cryptography::*;

    let path_wide: Vec<u16> = exe_path.as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();

    let mut cert_store = HCERTSTORE::default();
    let mut msg_handle: *mut core::ffi::c_void = std::ptr::null_mut();

    // SAFETY: path_wide is valid null-terminated; CryptQueryObject is safe for signed PE files.
    let ok = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            path_wide.as_ptr() as *const _,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut cert_store),
            Some(&mut msg_handle),
            None,
        )
    };
    if ok.is_err() {
        return None;
    }

    // Get signer info from PKCS7 message
    let mut signer_info_size: u32 = 0;
    // SAFETY: msg_handle is valid from CryptQueryObject success.
    let ok = unsafe {
        CryptMsgGetParam(
            msg_handle as *mut _,
            CMSG_SIGNER_INFO_PARAM, 0,
            None,
            &mut signer_info_size,
        )
    };
    if ok.is_err() || signer_info_size == 0 {
        return None;
    }

    let mut signer_info_buf = vec![0u8; signer_info_size as usize];
    // SAFETY: buffer is sized correctly.
    let ok = unsafe {
        CryptMsgGetParam(
            msg_handle as *mut _,
            CMSG_SIGNER_INFO_PARAM, 0,
            Some(signer_info_buf.as_mut_ptr() as *mut _),
            &mut signer_info_size,
        )
    };
    if ok.is_err() {
        return None;
    }

    // Parse CMSG_SIGNER_INFO to get Issuer + SerialNumber, then find cert in store
    // For simplicity: enumerate certs in store and return the first subject CN.
    // SAFETY: cert_store is valid from CryptQueryObject.
    let mut cert_ctx = unsafe {
        CertEnumCertificatesInStore(cert_store, None)
    };
    if cert_ctx.is_null() {
        return None;
    }

    // Extract subject name
    let mut name_buf = vec![0u16; 512];
    // SAFETY: cert_ctx is valid; name_buf is sized for 512 chars.
    let name_len = unsafe {
        CertGetNameStringW(
            cert_ctx,
            4, // CERT_NAME_SIMPLE_DISPLAY_TYPE
            0, // flags
            None,
            Some(&mut name_buf),
        )
    };

    // Cleanup
    unsafe {
        CertFreeCertificateContext(Some(cert_ctx));
        CertCloseStore(Some(cert_store), 0).ok();
    }

    if name_len <= 1 {
        return None;
    }
    let name = String::from_utf16_lossy(&name_buf[..name_len as usize - 1]);
    Some(name)
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

/// Pure helper: extract basename + modified time for cache key.
pub fn cache_key(path: &Path) -> Option<(PathBuf, u64)> {
    let canon = std::fs::canonicalize(path).ok()?;
    let mtime = std::fs::metadata(&canon).ok()?
        .modified().ok()?
        .duration_since(std::time::UNIX_EPOCH).ok()?
        .as_secs();
    Some((canon, mtime))
}

/// Cached trust verification. Skips WinVerifyTrust if (path, mtime) match.
pub struct TrustCache {
    inner: Mutex<HashMap<(PathBuf, u64), TrustLevel>>,
}

impl TrustCache {
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }

    pub fn verify(&self, path: &Path) -> TrustLevel {
        if let Some(key) = cache_key(path) {
            let guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(cached) = guard.get(&key) {
                return cached.clone();
            }
            drop(guard);

            let result = verify_signature(path);

            let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            guard.insert(key, result.clone());
            result
        } else {
            verify_signature(path)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_level_unsigned_is_not_trusted() {
        assert!(!TrustLevel::Unsigned.is_trusted());
    }

    #[test]
    fn trust_level_signed_is_trusted() {
        let t = TrustLevel::Signed { publisher: "Test".into() };
        assert!(t.is_trusted());
    }

    #[test]
    fn trust_level_untrusted_root_is_not_trusted() {
        assert!(!TrustLevel::SignedUntrustedRoot.is_trusted());
    }

    #[test]
    fn trust_level_error_is_not_trusted() {
        assert!(!TrustLevel::Error("err".into()).is_trusted());
    }

    #[test]
    fn verify_system_binary_catalog_signed() {
        // Windows system binaries use catalog signing (not embedded Authenticode).
        // WinVerifyTrust with WTD_CHOICE_FILE only checks embedded → returns Unsigned.
        // This is expected — we primarily care about third-party embedded-signed binaries.
        let path = Path::new(r"C:\Windows\System32\notepad.exe");
        if !path.exists() { return; }
        let t = verify_signature(path);
        // Catalog-signed → appears Unsigned to embedded-only check
        assert!(matches!(t, TrustLevel::Unsigned | TrustLevel::Signed { .. }),
            "notepad should be unsigned (catalog) or signed (if embedded check works): {t:?}");
    }

    #[test]
    fn verify_unsigned_open_source_binary() {
        // Many open-source tools (wezterm, cargo, etc) are NOT Authenticode-signed.
        // Our trust system correctly classifies them as Unsigned — they need
        // manual --trust or --guard scan to relax kernel mitigations.
        let path = std::env::current_exe().unwrap();
        let t = verify_signature(&path);
        assert!(!t.is_trusted(), "our test binary is unsigned: {t:?}");
    }

    #[test]
    fn verify_our_own_exe_is_unsigned() {
        // Our test binary is not Authenticode signed
        let path = std::env::current_exe().unwrap();
        let t = verify_signature(&path);
        assert!(!t.is_trusted(), "our test binary should be unsigned, got: {t:?}");
    }

    #[test]
    fn cache_returns_same_result() {
        let cache = TrustCache::new();
        let notepad = Path::new(r"C:\Windows\System32\notepad.exe");
        if !notepad.exists() { return; }
        let t1 = cache.verify(notepad);
        let t2 = cache.verify(notepad);
        assert_eq!(t1, t2);
    }

    #[test]
    fn cache_key_for_existing_file() {
        let notepad = Path::new(r"C:\Windows\System32\notepad.exe");
        if !notepad.exists() { return; }
        let key = cache_key(notepad);
        assert!(key.is_some());
    }

    #[test]
    fn cache_key_for_missing_file() {
        let key = cache_key(Path::new(r"C:\nonexistent\file.exe"));
        assert!(key.is_none());
    }
}
