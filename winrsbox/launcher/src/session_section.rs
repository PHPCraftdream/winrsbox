//! Publishes a `SessionConfig` snapshot via a session-scoped named shared
//! section (`Local\WinRsBoxSession`) so hooked processes can recover the
//! pipe name even when their environment has been scrubbed (notably MSYS2's
//! first-run helper children, which inherit an empty env).
//!
//! The handle returned by [`publish`] MUST be kept alive for the launcher's
//! whole runtime — closing the last handle to a named section destroys it
//! immediately, breaking late-arriving hook readers.

use anyhow::{anyhow, Context, Result};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_WRITE,
    MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READWRITE,
};

/// RAII guard owning the kernel object behind `Local\WinRsBoxSession`.
/// The section is reclaimed by the kernel when the last handle closes; we
/// hold ours until launcher exit so all child hook DLLs can keep reading.
pub struct SessionSectionHandle {
    handle: HANDLE,
}

impl Drop for SessionSectionHandle {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: handle was obtained from CreateFileMappingW above; no
            //         other code closes it.
            unsafe { CloseHandle(self.handle).ok() };
        }
    }
}

// SAFETY: HANDLE is a raw pointer but kernel objects are thread-safe; the
//         handle is opaque to user code after publish() returns.
unsafe impl Send for SessionSectionHandle {}
unsafe impl Sync for SessionSectionHandle {}

/// Serialize `cfg` and publish it into a fresh `Local\WinRsBoxSession`
/// named section. Returns the owning handle; drop it to release the
/// section.
pub fn publish(cfg: &ipc::SessionConfig) -> Result<SessionSectionHandle> {
    let bytes = cfg
        .to_section_bytes()
        .map_err(|e| anyhow!("session config encode failed: {e}"))?;

    let name_wide: Vec<u16> = OsStr::new(ipc::SESSION_CONFIG_SECTION_NAME)
        .encode_wide()
        .chain(Some(0))
        .collect();

    // SAFETY: INVALID_HANDLE_VALUE means "back by system pagefile"; size and
    //         name pointer are valid for the duration of the call.
    let handle = unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            None,
            PAGE_READWRITE,
            0,
            ipc::SESSION_CONFIG_SECTION_SIZE as u32,
            PCWSTR(name_wide.as_ptr()),
        )
        .context("CreateFileMappingW for session section")?
    };

    // SAFETY: handle is valid (CreateFileMappingW succeeded). Map the entire
    //         section for write access. View is unmapped via the
    //         scoped-guard pattern below so a write failure cannot leak it.
    let view: MEMORY_MAPPED_VIEW_ADDRESS = unsafe {
        MapViewOfFile(
            handle,
            FILE_MAP_WRITE,
            0,
            0,
            ipc::SESSION_CONFIG_SECTION_SIZE,
        )
    };
    if view.Value.is_null() {
        // SAFETY: handle is valid.
        unsafe { CloseHandle(handle).ok() };
        return Err(anyhow!("MapViewOfFile returned null"));
    }

    // SAFETY: view points to a writeable mapping of at least
    //         SESSION_CONFIG_SECTION_SIZE bytes; bytes.len() <= that bound
    //         (enforced by to_section_bytes).
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), view.Value as *mut u8, bytes.len());
    }
    // SAFETY: view was just returned by MapViewOfFile.
    unsafe { UnmapViewOfFile(view).ok() };

    Ok(SessionSectionHandle { handle })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_and_read_roundtrip() {
        let cfg = ipc::SessionConfig {
            pipe_name: format!(r"\\.\pipe\winrsbox-test-{}", std::process::id()),
            dll_path: r"D:\bin\hook.dll".into(),
            cwd: r"D:\sandbox".into(),
            sandbox_root: r"D:\sandbox_root".into(),
            overlay_roots: vec![],
            trace: true,
            guard: "scan".into(),
            allow_rwx: false,
            disable_hooks: String::new(),
        };
        let _h = publish(&cfg).expect("publish ok");

        // Read it back via OpenFileMappingW + MapViewOfFile.
        use windows::Win32::System::Memory::{
            FILE_MAP_READ, OpenFileMappingW,
        };
        let name_wide: Vec<u16> = OsStr::new(ipc::SESSION_CONFIG_SECTION_NAME)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let reader = unsafe {
            OpenFileMappingW(FILE_MAP_READ.0, false, PCWSTR(name_wide.as_ptr()))
                .expect("OpenFileMappingW")
        };
        let view = unsafe {
            MapViewOfFile(
                reader,
                FILE_MAP_READ,
                0,
                0,
                ipc::SESSION_CONFIG_SECTION_SIZE,
            )
        };
        assert!(!view.Value.is_null());
        let slice = unsafe {
            std::slice::from_raw_parts(
                view.Value as *const u8,
                ipc::SESSION_CONFIG_SECTION_SIZE,
            )
        };
        let dec = ipc::SessionConfig::from_section_bytes(slice).unwrap();
        assert_eq!(dec.pipe_name, cfg.pipe_name);
        assert_eq!(dec.dll_path, cfg.dll_path);
        assert!(dec.trace);
        unsafe { UnmapViewOfFile(view).ok() };
        unsafe { CloseHandle(reader).ok() };
    }
}
