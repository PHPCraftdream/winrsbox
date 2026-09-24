// Device-namespace classification for opens the DOS-path pipeline could not resolve.

use super::*;

/// What the device classification says about an open whose path the policy
/// pipeline could not resolve to a DOS path.
///
/// Three-valued on purpose. The caller's fail-closed rule for an unresolvable
/// write ("deny — it would reach the real disk outside the overlay") is right
/// for filesystem-shaped targets and wrong for devices that have no
/// filesystem behind them at all. Collapsing `PassThrough` into "no verdict"
/// is what denied every named-pipe and console open carrying write access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeviceVerdict {
    /// Refuse the open outright, in either direction.
    Deny(NTSTATUS),
    /// A non-filesystem device the sandbox deliberately passes through:
    /// named pipes, sockets, the console and NUL. A write to one of these
    /// cannot reach the real filesystem, so the caller's dead-end write deny
    /// must NOT apply. This is what `CreatePipe`, `child_process.spawn` and
    /// every console TTY open depend on.
    PassThrough,
    /// No device verdict — either not a device path at all, or a filesystem
    /// volume device (`\Device\HarddiskVolumeN\…`), which is exactly the raw
    /// form the dead-end deny exists to stop. The caller's own rules apply.
    Unhandled,
}

/// Classify the raw NT path in `attrs` for an open in the requested direction:
/// - hard blocks (shadowcopy, physicaldrive, raw harddisk, dangerous pipe,
///   credential surfaces) — `Deny` regardless of direction;
/// - UNC/network-redirector targets (`DeviceKind::NetworkPath`, P0-03) and
///   unrecognized system devices (`DeviceKind::SystemQuery`) — `Deny` when
///   `write` is set. A write here would reach the real disk/volume/share
///   outside the CoW overlay with no `decide()` call; reads keep the
///   documented pass-through ("reads outside project_root hit the real
///   disk");
/// - named pipes, sockets, console and NUL — `PassThrough` in both
///   directions;
/// - volume devices and non-device paths — `Unhandled`.
///
/// SAFETY: `attrs` must be valid per NT calling convention.
pub(crate) unsafe fn classify_device_open(
    attrs: *const OBJECT_ATTRIBUTES,
    write: bool,
) -> DeviceVerdict {
    let by_name = classify_by_name(attrs, write);
    if by_name != DeviceVerdict::Unhandled || attrs.is_null() {
        return by_name;
    }
    // A relative open is parsed inside the RootDirectory handle's own device,
    // so a name we cannot map (typically empty: "reopen this handle") is
    // judged by that device. MSYS/Cygwin's fork emulation opens the write end
    // of its process-tracker pipe exactly this way; denying it killed every
    // external command run from git-bash ("prefork: couldn't create pipe
    // process tracker, Win32 error 5").
    let root = (*attrs).RootDirectory;
    if root.is_null() {
        return DeviceVerdict::Unhandled;
    }
    verdict_for_root_device(handle_device_type(root))
}

/// NT device types with no filesystem behind them (winioctl.h).
const FILE_DEVICE_NAMED_PIPE: u32 = 0x11;
const FILE_DEVICE_NULL: u32 = 0x15;
const FILE_DEVICE_CONSOLE: u32 = 0x50;

/// Verdict for a relative open from the device type of its RootDirectory:
/// named-pipe, NUL and console roots cannot reach a filesystem; anything else
/// (disk, unknown, query failure) keeps the caller's own rules.
pub(crate) fn verdict_for_root_device(device_type: Option<u32>) -> DeviceVerdict {
    match device_type {
        Some(FILE_DEVICE_NAMED_PIPE | FILE_DEVICE_NULL | FILE_DEVICE_CONSOLE) => {
            DeviceVerdict::PassThrough
        }
        _ => DeviceVerdict::Unhandled,
    }
}

/// Device type of the file object behind `handle`, or None if the query fails.
///
/// SAFETY: `handle` is only passed to the kernel, which validates it.
unsafe fn handle_device_type(handle: HANDLE) -> Option<u32> {
    use ntapi::ntioapi::{
        FileFsDeviceInformation, NtQueryVolumeInformationFile, FILE_FS_DEVICE_INFORMATION,
    };
    let mut info: FILE_FS_DEVICE_INFORMATION = std::mem::zeroed();
    let mut iosb: IO_STATUS_BLOCK = std::mem::zeroed();
    let status = NtQueryVolumeInformationFile(
        handle,
        &mut iosb,
        &mut info as *mut _ as *mut _,
        std::mem::size_of::<FILE_FS_DEVICE_INFORMATION>() as u32,
        FileFsDeviceInformation,
    );
    (status >= 0).then_some(info.DeviceType)
}

/// Classification from the ObjectName alone (the original rule).
unsafe fn classify_by_name(attrs: *const OBJECT_ATTRIBUTES, write: bool) -> DeviceVerdict {
    let Some(dev_path) = extract_raw_nt_path(attrs) else {
        return DeviceVerdict::Unhandled;
    };
    let utf16: Vec<u16> = dev_path.encode_utf16().collect();
    let Some(device) = policy::dev::nt_to_device_path(&utf16) else {
        return DeviceVerdict::Unhandled;
    };
    let kind = policy::dev::classify_device(&device);
    // Exhaustive on DeviceKind — a future variant must decide explicitly
    // here rather than silently inherit "carry on".
    let verdict = match kind {
        policy::dev::DeviceKind::Unknown => DeviceVerdict::Deny(STATUS_ACCESS_DENIED),
        policy::dev::DeviceKind::NetworkPath | policy::dev::DeviceKind::SystemQuery => {
            if write {
                DeviceVerdict::Deny(STATUS_ACCESS_DENIED)
            } else {
                DeviceVerdict::Unhandled
            }
        }
        policy::dev::DeviceKind::NamedPipe
        | policy::dev::DeviceKind::Socket
        | policy::dev::DeviceKind::Console
        | policy::dev::DeviceKind::Null => DeviceVerdict::PassThrough,
        // A volume device is filesystem-shaped: it must stay subject to the
        // caller's dead-end deny, which is the whole point of that rule.
        policy::dev::DeviceKind::HarddiskVolume => DeviceVerdict::Unhandled,
    };
    if matches!(verdict, DeviceVerdict::Deny(_)) && is_trace() {
        ipc_log(
            ipc::LogLevel::Trace,
            format!("DENY device: {dev_path} kind={kind:?} write={write}"),
        );
    }
    verdict
}

/// Returns true if the path in `attrs` refers to a filesystem volume device
/// (`\Device\HarddiskVolumeN\...`). Used to deny writes through device-path
/// forms that bypass the DOS-path policy pipeline.
///
/// # Safety
/// `attrs` must be valid per NT calling convention.
pub(crate) unsafe fn is_fs_device_path(attrs: *const OBJECT_ATTRIBUTES) -> bool {
    let Some(raw) = extract_raw_nt_path(attrs) else { return false };
    let utf16: Vec<u16> = raw.encode_utf16().collect();
    let Some(device) = policy::dev::nt_to_device_path(&utf16) else { return false };
    matches!(policy::dev::classify_device(&device), policy::dev::DeviceKind::HarddiskVolume)
}

// ---------------------------------------------------------------------------
// Post-open reparse verification + 8.3 short-name resolution
// ---------------------------------------------------------------------------

// NOTE: post-open junction/symlink verification removed — false positives on
// legitimate DLL/path-canonicalization differences. Junctions can still be
// closed by hooking NtCreateFile with FILE_FLAG_OPEN_REPARSE_POINT and
// blocking the create-side (separate task).

#[cfg(test)]
mod root_device_tests {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::namedpipeapi::CreateNamedPipeW;
    use winapi::um::winbase::{FILE_FLAG_BACKUP_SEMANTICS, PIPE_ACCESS_INBOUND};
    use winapi::um::winnt::{FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ};

    fn wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
    }

    /// `classify_device_open` for an empty-name open relative to `root`.
    fn classify_empty_relative(root: HANDLE, write: bool) -> DeviceVerdict {
        let oa = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: root,
            ObjectName: std::ptr::null_mut(),
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        // SAFETY: oa is a valid local for the duration of the call.
        unsafe { classify_device_open(&oa, write) }
    }

    #[test]
    fn root_device_type_mapping() {
        assert_eq!(verdict_for_root_device(Some(FILE_DEVICE_NAMED_PIPE)), DeviceVerdict::PassThrough);
        assert_eq!(verdict_for_root_device(Some(FILE_DEVICE_NULL)), DeviceVerdict::PassThrough);
        assert_eq!(verdict_for_root_device(Some(FILE_DEVICE_CONSOLE)), DeviceVerdict::PassThrough);
        // FILE_DEVICE_DISK / DISK_FILE_SYSTEM stay subject to the dead-end deny.
        assert_eq!(verdict_for_root_device(Some(0x07)), DeviceVerdict::Unhandled);
        assert_eq!(verdict_for_root_device(Some(0x08)), DeviceVerdict::Unhandled);
        assert_eq!(verdict_for_root_device(None), DeviceVerdict::Unhandled);
    }

    /// Regression: MSYS/Cygwin `prefork` opens its process-tracker pipe's
    /// other end with an empty name relative to the pipe handle. Denying it
    /// broke every external command started from git-bash.
    #[test]
    fn empty_name_relative_to_pipe_passes_write() {
        let name = wide(&format!(r"\\.\pipe\winrsbox-test-rootdev-{}", std::process::id()));
        // SAFETY: valid NUL-terminated name; default security.
        let pipe = unsafe {
            CreateNamedPipeW(name.as_ptr(), PIPE_ACCESS_INBOUND, 0, 1, 512, 512, 0, std::ptr::null_mut())
        };
        assert_ne!(pipe, INVALID_HANDLE_VALUE, "CreateNamedPipeW failed");
        assert_eq!(classify_empty_relative(pipe as HANDLE, true), DeviceVerdict::PassThrough);
        // SAFETY: pipe is a valid handle owned by this test.
        unsafe { CloseHandle(pipe) };
    }

    /// Negative control: the same shape relative to a directory on disk must
    /// NOT pass through — that would reach the real filesystem undecided.
    #[test]
    fn empty_name_relative_to_disk_directory_stays_unhandled() {
        let dir = wide(&std::env::temp_dir().to_string_lossy());
        // SAFETY: valid NUL-terminated path; BACKUP_SEMANTICS opens a directory.
        let h = unsafe {
            CreateFileW(
                dir.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(h, INVALID_HANDLE_VALUE, "open temp dir failed");
        assert_eq!(classify_empty_relative(h as HANDLE, true), DeviceVerdict::Unhandled);
        // SAFETY: h is a valid handle owned by this test.
        unsafe { CloseHandle(h) };
    }
}

/// Check if a path contains an 8.3 short-name pattern (tilde followed by digit).
pub(crate) fn needs_short_name_resolve(path: &str) -> bool {
    let bytes = path.as_bytes();
    for i in 0..bytes.len().saturating_sub(1) {
        if bytes[i] == b'~' && bytes[i + 1].is_ascii_digit() {
            return true;
        }
    }
    false
}

/// Only a spelling that expands to a different name is an 8.3 alias.
/// Relative paths are deferred until their base is resolved; unknown absolute paths are denied.
pub(crate) fn short_name_alias_or_unknown(path: &str) -> bool {
    use std::os::windows::ffi::OsStrExt;
    let mut current = std::path::Path::new(path);
    // Relative names are checked again after resolve_for_hook has pinned their
    // actual base directory; resolving them here could use a different base.
    if !current.is_absolute() {
        return false;
    }
    loop {
        let wide: Vec<u16> = current.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut stack = [0u16; 512];
        // SAFETY: wide is NUL-terminated; stack is writable for its full length.
        let count = unsafe {
            winapi::um::fileapi::GetLongPathNameW(
                wide.as_ptr(), stack.as_mut_ptr(), stack.len() as u32,
            )
        };
        if count == 0 {
            // SAFETY: reads this thread's immediately preceding Win32 error.
            let error = unsafe { winapi::um::errhandlingapi::GetLastError() };
            // GetLongPathNameW can leave ERROR_SUCCESS for a missing leaf
            // inside a hooked process; existing parents are still checked.
            if error != winapi::shared::winerror::ERROR_SUCCESS
                && error != winapi::shared::winerror::ERROR_FILE_NOT_FOUND
                && error != winapi::shared::winerror::ERROR_PATH_NOT_FOUND
            {
                return true;
            }
            current = match current.parent() {
                Some(parent) if parent != current => parent,
                _ => return true,
            };
            continue;
        }
        let expanded = if (count as usize) < stack.len() {
            String::from_utf16_lossy(&stack[..count as usize])
        } else {
            if count > 32 * 1024 {
                return true;
            }
            let mut big = vec![0u16; count as usize];
            // SAFETY: wide is NUL-terminated; big has the size requested by Win32.
            let copied = unsafe {
                winapi::um::fileapi::GetLongPathNameW(
                    wide.as_ptr(), big.as_mut_ptr(), big.len() as u32,
                )
            };
            if copied == 0 || copied as usize >= big.len() {
                return true;
            }
            String::from_utf16_lossy(&big[..copied as usize])
        };
        return policy::path::nt_case_fold(&expanded)
            != policy::path::nt_case_fold(&current.to_string_lossy());
    }
}

/// Keep a no-reparse relative open off the DOS drive-name symlink.
pub(super) fn device_nt_for_folded_dos(base: &[u16], folded_dos: &[u16]) -> Option<Vec<u16>> {
    use super::path_resolve::{ascii_to_lower_u16, device_drive_map};
    let nt_prefix = folded_dos.starts_with(&[b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16])
        || folded_dos.starts_with(&[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16]);
    if folded_dos.len() < 7
        || !nt_prefix
        || !matches!(folded_dos[4], 0x41..=0x5A | 0x61..=0x7A)
        || folded_dos[5] != b':' as u16
        || folded_dos[6] != b'\\' as u16
    {
        return None;
    }
    let drive = ascii_to_lower_u16(folded_dos[4]);
    let lower_base: Vec<u16> = base.iter().copied().map(ascii_to_lower_u16).collect();
    for (device, letter) in device_drive_map() {
        if *letter != drive || !lower_base.starts_with(device) {
            continue;
        }
        if lower_base.get(device.len()).is_some_and(|unit| *unit != b'\\' as u16) {
            continue;
        }
        let mut path = Vec::with_capacity(device.len() + folded_dos.len() - 6);
        path.extend_from_slice(&base[..device.len()]);
        path.extend_from_slice(&folded_dos[6..]);
        return Some(path);
    }
    None
}

#[cfg(test)]
mod short_name_tests {
    use super::*;

    #[test]
    fn literal_tilde_digit_name_survives_the_denylist() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = std::fs::canonicalize(dir.path()).unwrap();
        let canonical = canonical.to_string_lossy();
        let parent = canonical.strip_prefix(r"\\?\UNC\")
            .map(|rest| format!(r"\\{rest}"))
            .or_else(|| canonical.strip_prefix(r"\\?\").map(str::to_string))
            .unwrap_or_else(|| canonical.into_owned());
        let parent = std::path::Path::new(&parent);
        let file = parent.join("9710~0.js");
        std::fs::write(&file, b"fixture").unwrap();
        let literal = file.to_string_lossy();
        assert!(needs_short_name_resolve(&literal));
        assert!(!short_name_alias_or_unknown(&literal));
        assert!(canonical_denylist_status(&canonicalize_for_denylist(&literal)).is_none());
        assert!(!short_name_alias_or_unknown(
            &parent.join("new~0.js").to_string_lossy()
        ));
        let relative = format!("winrsbox-missing-{}~0.js", std::process::id());
        assert!(!std::path::Path::new(&relative).exists());
        assert!(!short_name_alias_or_unknown(&relative));
        assert!(canonical_denylist_status(&canonicalize_for_denylist(&relative)).is_none());
    }

    #[test]
    fn resolved_bare_relative_literal_tilde_digit_is_not_treated_as_alias() {
        let name = format!("winrsbox-missing-{}~0.js", std::process::id());
        assert!(!std::path::Path::new(&name).exists());
        let buf: Vec<u16> = name.encode_utf16().collect();
        let len_bytes = (buf.len() * 2) as u16;
        let us = UNICODE_STRING {
            Length: len_bytes,
            MaximumLength: len_bytes,
            Buffer: buf.as_ptr() as *mut u16,
        };
        let oa = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: &us as *const UNICODE_STRING as *mut UNICODE_STRING,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        // SAFETY: us, oa, and buf remain valid for the duration of resolution.
        let (dos, kernel_path) = unsafe { resolve_for_hook(&oa) }.expect("relative path resolves");
        assert!(kernel_path.is_some(), "resolved path is reused for the kernel open");
        assert!(canonical_denylist_status(&canonicalize_for_denylist(&dos)).is_none());
    }

    #[test]
    fn existing_short_alias_is_denied_when_windows_provides_one() {
        let alias = r"C:\PROGRA~1";
        if std::path::Path::new(alias).exists() {
            assert!(short_name_alias_or_unknown(alias));
            let missing_child = format!(r"C:\PROGRA~1\winrsbox-missing-{}~0.js", std::process::id());
            assert!(!std::path::Path::new(&missing_child).exists());
            assert!(short_name_alias_or_unknown(&missing_child));
        }
    }
}
