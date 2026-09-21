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