// path_info_guard — NtQueryInformationFile hook.
//
// Masks the overlay storage path returned by `NtQueryInformationFile` for the
// `FileNormalizedNameInformation` (48) class only. Modern Windows 10/11
// `GetFinalPathNameByHandleW` builds its DOS result from the class-48 path:
// it resolves the handle volume's drive letter via the Mount Manager and glues
// it onto the class-48 volume-relative tail. Masking class 48 rewrites that
// tail back to the virtual path, so the assembled DOS path carries no
// `.winrsbox` / `workdir` markers and does not break the glue (the volume is
// unchanged, so the drive letter still resolves correctly).
//
// Class 9 (`FileNameInformation`) is intentionally LEFT PASSTHROUGH. Modern
// kernel32 cross-checks the class-9 and class-48 results and returns
// ERROR_ACCESS_DENIED when they disagree (masking class 9 alone or alongside
// class 48 reproducibly breaks GetFinalPathNameByHandleW). Since class 48 is
// the one `GetFinalPathNameByHandleW` actually uses for the DOS build, leaving
// class 9 untouched is the strictly-better, non-regressing choice.
//
// The kernel returns the REAL overlay path (e.g.
// `\Users\me\.winrsbox\sbx\workdir\d\proj\.git\HEAD`) for a handle the sandbox
// redirected. We rewrite it back to the virtual volume-relative form
// (`\proj\.git\HEAD`). Fail-open: on any doubt we leave the buffer untouched
// and never break the application's call.

use std::sync::OnceLock;

use detour2::GenericDetour;
use ntapi::ntioapi::IO_STATUS_BLOCK;
use ntapi::winapi::shared::ntdef::HANDLE;
use ntapi::winapi::shared::ntdef::NTSTATUS;
use winapi::ctypes::c_void;

use crate::anti_rec;
use crate::hooks;

// ---------------------------------------------------------------------------
// Type alias + detour storage
// ---------------------------------------------------------------------------

type FnNtQueryInformationFile = unsafe extern "system" fn(
    HANDLE,                  // FileHandle
    *mut IO_STATUS_BLOCK,    // IoStatusBlock
    *mut c_void,             // FileInformation
    u32,                     // Length
    u32,                     // FileInformationClass
) -> NTSTATUS;

static HOOK_NT_QUERY_INFORMATION_FILE: OnceLock<GenericDetour<FnNtQueryInformationFile>> =
    OnceLock::new();

// ---------------------------------------------------------------------------
// FileInformationClass constants
// ---------------------------------------------------------------------------

/// `FileNormalizedNameInformation` — the class modern Windows 10/11
/// `GetFinalPathNameByHandleW` uses to build its DOS result. This is the only
/// class we mask (see the module doc for why class 9 is left passthrough).
const FILE_NORMALIZED_NAME_INFORMATION_CLASS: u32 = 48;

/// Layout of FILE_NAME_INFORMATION:
///   0x00: ULONG FileNameLength   (bytes, not chars)
///   0x04: WCHAR FileName[1]
const NAME_LEN_OFF: usize = 0x00;
const NAME_OFF: usize = 0x04;

// ---------------------------------------------------------------------------
// Pure buffer rewriter
//
// Extracted from the unsafe hook body so it is unit-testable without FFI.
// Returns the rewritten buffer (bytes) when masking was applied; None when the
// path is not inside the overlay or rewriting is unsafe (caller leaves the
// original buffer untouched).
// ---------------------------------------------------------------------------

/// Attempt to rewrite a `FILE_NAME_INFORMATION` buffer so that an overlay
/// volume-relative path is mapped back to the virtual volume-relative path.
///
/// Inputs:
///   - `buf`:       the raw bytes of the FILE_NAME_INFORMATION structure. At
///                  least `NAME_OFF` (4) bytes must be present; the FileName
///                  WCHAR array is read out of `buf[NAME_OFF..]` using the
///                  embedded FileNameLength field (with a bounds guard).
///   - `sandbox_root`: the overlay storage root as an absolute DOS path WITH
///                  a drive letter (e.g. `C:\Users\me\.winrsbox\sbx\workdir`),
///                  case-insensitive. This is exactly what `hooks::SANDBOX_ROOT`
///                  holds.
///
/// Returns `Some(new_bytes)` with a rewritten buffer on success, or `None` when:
///   - the buffer is too small to read FileNameLength,
///   - the embedded FileNameLength exceeds the buffer,
///   - the path is NOT inside the overlay (passthrough),
///   - `unmirror_from_overlay` could not recover a virtual path,
///   - the rewritten FileName would NOT fit in the original buffer slot
///     (fail-open: we never truncate / extend, only overwrite in place when
///     the new content is ≤ the old content).
pub(crate) fn rewrite_file_name_information(
    buf: &[u8],
    sandbox_root: &str,
) -> Option<Vec<u8>> {
    // Need FileNameLength (u32) at offset 0.
    if buf.len() < NAME_LEN_OFF + 4 {
        return None;
    }
    let name_len = u32::from_le_bytes([
        buf[NAME_LEN_OFF], buf[NAME_LEN_OFF + 1],
        buf[NAME_LEN_OFF + 2], buf[NAME_LEN_OFF + 3],
    ]) as usize;
    // The FileName WCHAR array lives at NAME_OFF; it must fit within the buffer.
    if name_len < 2 || NAME_OFF + name_len > buf.len() {
        return None;
    }

    // Decode the volume-relative UTF-16 path (e.g. `\Users\me\…\workdir\d\proj`).
    let chars = name_len / 2;
    let mut name_u16 = vec![0u16; chars];
    for (i, slot) in name_u16.iter_mut().enumerate() {
        let off = NAME_OFF + i * 2;
        *slot = u16::from_le_bytes([buf[off], buf[off + 1]]);
    }
    // FileName does not include a drive letter; it begins with `\`.
    let overlay_rel = String::from_utf16_lossy(&name_u16);

    // Build the overlay DOS path by prepending the SANDBOX_ROOT drive letter.
    // The overlay always lives on the same volume as sandbox_root, so the
    // drive letter of the handle's volume equals sandbox_root's drive letter.
    let drive_letter = sandbox_root
        .as_bytes()
        .first()
        .copied()
        .filter(|c| c.is_ascii_alphabetic())?;
    // Preserve the original case of the kernel-reported path — only the
    // prefix-match against sandbox_root is case-insensitive. Lowercasing the
    // input here would corrupt the virtual path's case (e.g. `HEAD` → `head`).
    let mut overlay_dos = String::with_capacity(2 + overlay_rel.len());
    overlay_dos.push(drive_letter as char);
    overlay_dos.push(':');
    // overlay_rel begins with `\`; append verbatim.
    overlay_dos.push_str(&overlay_rel);

    // Match against sandbox_root (case-insensitive). Require a path-component
    // boundary so `C:\sb` does not prefix-match `C:\sbx\…`. Compare a lowercased
    // copy of the overlay path against the lowercased root.
    let root_lower = sandbox_root.to_ascii_lowercase();
    let root_trimmed = root_lower.trim_end_matches('\\');
    if root_trimmed.is_empty() {
        return None;
    }
    let overlay_dos_lower = overlay_dos.to_ascii_lowercase();
    let overlay_root_prefix_lower = overlay_dos_lower.get(..root_trimmed.len())?;
    if overlay_root_prefix_lower != root_trimmed {
        // Not inside the overlay — leave the buffer untouched.
        return None;
    }
    // Boundary check: byte after the prefix must be `\` (or the path equals it).
    if overlay_dos_lower.len() > root_trimmed.len()
        && overlay_dos_lower.as_bytes()[root_trimmed.len()] != b'\\'
    {
        return None;
    }

    // Recover the virtual DOS path (`d:\proj\.git\HEAD`). unmirror_from_overlay
    // uses Path::strip_prefix which is case-SENSITIVE, so we must pass the root
    // exactly as it appears in the kernel-reported overlay path (preserving the
    // original case), not the lowercased sandbox_root. Slice it out of the
    // case-preserved overlay_dos using the length we just validated.
    let overlay_root_preserved = &overlay_dos[..root_trimmed.len()];
    let overlay_pbuf = std::path::PathBuf::from(&overlay_dos);
    let virtual_dos = policy::path::unmirror_from_overlay(
        &overlay_pbuf,
        std::path::Path::new(overlay_root_preserved),
    )?;

    // FileNameInformation semantically returns a path RELATIVE TO THE VOLUME,
    // without a drive letter. Strip the `<letter>:` prefix from the virtual
    // DOS path to produce `\proj\.git\HEAD`.
    let virtual_rel = strip_drive_prefix(&virtual_dos);

    // Encode the new FileName as UTF-16.
    let new_u16: Vec<u16> = virtual_rel.encode_utf16().collect();
    let new_name_bytes = new_u16.len() * 2;

    // Fail-open: if the new content would NOT fit in the original slot, leave
    // the buffer as-is. We only ever shorten in place.
    if new_name_bytes > name_len {
        return None;
    }

    // Build the rewritten buffer: copy the original, then overwrite FileName
    // and FileNameLength. Trailing bytes after the new name are zeroed so a
    // reader honouring FileNameLength sees clean data (the kernel fills the
    // tail with whatever was there; for masking correctness we clear it).
    let mut out = buf.to_vec();
    // New FileNameLength (bytes).
    out[NAME_LEN_OFF..NAME_LEN_OFF + 4]
        .copy_from_slice(&(new_name_bytes as u32).to_le_bytes());
    // New FileName WCHARs.
    for (i, &u) in new_u16.iter().enumerate() {
        let off = NAME_OFF + i * 2;
        out[off..off + 2].copy_from_slice(&u.to_le_bytes());
    }
    // Zero the slack between new_name_bytes and the old name_len so no stale
    // overlay bytes leak past FileNameLength.
    let slack_start = NAME_OFF + new_name_bytes;
    let slack_end = NAME_OFF + name_len;
    for b in &mut out[slack_start..slack_end] {
        *b = 0;
    }
    Some(out)
}

/// Strip the leading `<letter>:` drive prefix from a DOS path, returning the
/// volume-relative form `\rest\of\path`. Leaves the path unchanged when no
/// drive letter is present (defensive — unmirror always yields `<letter>:`).
fn strip_drive_prefix(dos: &str) -> &str {
    let b = dos.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        &dos[2..]
    } else {
        dos
    }
}

// ---------------------------------------------------------------------------
// Hook implementation
// ---------------------------------------------------------------------------

unsafe extern "system" fn hook_nt_query_information_file(
    file_handle: HANDLE,
    io_status_block: *mut IO_STATUS_BLOCK,
    file_information: *mut c_void,
    length: u32,
    file_information_class: u32,
) -> NTSTATUS {
    let call_original = || {
        HOOK_NT_QUERY_INFORMATION_FILE
            .get()
            .unwrap()
            .call(file_handle, io_status_block, file_information, length, file_information_class)
    };

    // Only FileNormalizedNameInformation (48) is masked.
    //
    // WHY ONLY CLASS 48:
    //   Modern Windows 10/11 `GetFinalPathNameByHandleW` builds its DOS result
    //   from the class-48 (normalized) volume-relative path — it glues this
    //   path's volume's drive letter (resolved separately via the Mount
    //   Manager using the device name from NtQueryObject) onto the
    //   volume-relative tail returned by class 48. Masking class 48 thus
    //   produces a clean virtual DOS path with no overlay markers, and does
    //   not break the glue (the drive letter still resolves correctly because
    //   the handle's volume is unchanged).
    //
    //   Masking class 9 (FileNameInformation) BREAKS GetFinalPathNameByHandleW
    //   with ERROR_ACCESS_DENIED: modern kernel32 cross-checks the class-9
    //   and class-48 results and rejects the call when they disagree (class 9
    //   would be the masked virtual path while class 48 / NtQueryObject still
    //   carry the overlay path). Therefore class 9 is intentionally left
    //   passthrough. This is a strict improvement over the pre-fix behaviour
    //   for the one API (`GetFinalPathNameByHandleW`) that actually leaked
    //   the overlay path in practice, and does not regress any caller.
    if file_information_class != FILE_NORMALIZED_NAME_INFORMATION_CLASS {
        return call_original();
    }

    // Anti-recursion: GetFinalPathNameByHandleW may re-enter
    // NtQueryInformationFile. On re-entry the guard returns None and we call
    // the original without rewriting (the outer call already rewrote).
    let Some(_guard) = anti_rec::enter() else {
        return call_original();
    };

    let status = call_original();
    if status != 0 {
        return status;
    }

    let Some(sandbox_root) = hooks::SANDBOX_ROOT.get() else {
        // No overlay configured — nothing to mask.
        return status;
    };
    if sandbox_root.is_empty() {
        return status;
    }
    if file_information.is_null() || length == 0 {
        return status;
    }

    // IoStatusBlock.Information (offset 8 on x64) carries the number of bytes
    // the kernel actually wrote into FileInformation. Use it as the readable
    // span, clamped to the caller-declared Length. When IoStatusBlock is null
    // or Information is 0/oversized, fall back to `length`.
    let info_size = if !io_status_block.is_null() {
        // SAFETY: read of Information at offset 8 on x64 — pointer validated above.
        let v = *((io_status_block as *const u8).add(8) as *const usize);
        if v != 0 && v <= length as usize {
            v
        } else {
            length as usize
        }
    } else {
        length as usize
    };
    if info_size < NAME_OFF + 2 {
        return status;
    }

    // SAFETY: file_information is non-null and the kernel just wrote info_size
    // bytes into it (≤ length). We treat that span as a &[u8] for the pure
    // rewriter, then copy the result back if it changed.
    let buf_slice: &[u8] = std::slice::from_raw_parts(
        file_information as *const u8,
        info_size,
    );

    let Some(rewritten) = rewrite_file_name_information(buf_slice, sandbox_root) else {
        return status;
    };
    if rewritten.len() != info_size {
        // Defensive: rewrite always returns same length (it overwrites in
        // place). If this ever fires, do not touch the live buffer.
        if hooks::is_trace() {
            hooks::ipc_log(
                ipc::LogLevel::Trace,
                format!("path_info_guard: length mismatch {info_size} vs {}", rewritten.len()),
            );
        }
        return status;
    }

    // SAFETY: copy rewritten bytes back over the caller's buffer. Same length,
    // valid destination (the kernel wrote into it a moment ago).
    std::ptr::copy_nonoverlapping(
        rewritten.as_ptr(),
        file_information as *mut u8,
        info_size,
    );

    // Shrink IoStatusBlock.Information to reflect the rewritten FILE_NAME_INFORMATION
    // total size (header + new FileNameLength). The kernel set Information to the
    // ORIGINAL overlay path size; consumers that read Information instead of the
    // embedded FileNameLength (e.g. GetFinalPathNameByHandleW on some builds)
    // would otherwise read trailing zero-slack as part of the name or fail
    // validation. The new size is NAME_OFF + new FileNameLength, never larger
    // than the original info_size (we only shorten).
    let new_name_len = u32::from_le_bytes([
        rewritten[NAME_LEN_OFF], rewritten[NAME_LEN_OFF + 1],
        rewritten[NAME_LEN_OFF + 2], rewritten[NAME_LEN_OFF + 3],
    ]) as usize;
    let new_info_size = NAME_OFF + new_name_len;
    if new_info_size <= info_size && !io_status_block.is_null() {
        // SAFETY: IoStatusBlock.Information is the usize at offset 8 on x64.
        // We only ever shrink it (new_info_size ≤ original), so it stays within
        // the caller-declared Length.
        let info_ptr = (io_status_block as *mut u8).add(8) as *mut usize;
        *info_ptr = new_info_size;
    }

    if hooks::is_trace() {
        hooks::ipc_log(
            ipc::LogLevel::Trace,
            format!("path_info_guard: masked overlay path in FileNameInformation (info {info_size}→{new_info_size})"),
        );
    }
    status
}

// ---------------------------------------------------------------------------
// Install / uninstall
// ---------------------------------------------------------------------------

pub unsafe fn install() -> Result<(), Box<dyn std::error::Error>> {
    let addr = hooks::ntdll_export(b"NtQueryInformationFile\0")
        .ok_or_else(|| "ntdll export not found: NtQueryInformationFile".to_string())?;
    // SAFETY: addr is the real ntdll!NtQueryInformationFile export; ABI matches
    // the FnNtQueryInformationFile type alias.
    let target: FnNtQueryInformationFile = std::mem::transmute(addr as usize);
    let hook_ptr: FnNtQueryInformationFile = hook_nt_query_information_file;
    let detour = GenericDetour::<FnNtQueryInformationFile>::new(target, hook_ptr)
        .map_err(|e| format!("detour init NtQueryInformationFile: {:?}", e))?;
    // Populate OnceLock BEFORE enabling so the hook never observes an empty lock.
    HOOK_NT_QUERY_INFORMATION_FILE.set(detour).ok();
    HOOK_NT_QUERY_INFORMATION_FILE
        .get()
        .expect("set above")
        .enable()
        .map_err(|e| format!("detour enable NtQueryInformationFile: {:?}", e))?;
    Ok(())
}

pub unsafe fn uninstall() {
    if let Some(h) = HOOK_NT_QUERY_INFORMATION_FILE.get() {
        let _ = h.disable();
    }
}

// ---------------------------------------------------------------------------
// Unit tests (pure helpers — no FFI)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// Build a FILE_NAME_INFORMATION byte buffer from a volume-relative path
    /// string. FileNameLength is the byte count of the UTF-16 encoding.
    fn build_fni(vol_rel: &str) -> Vec<u8> {
        let u16s: Vec<u16> = vol_rel.encode_utf16().collect();
        let name_bytes = u16s.len() * 2;
        let mut buf = vec![0u8; NAME_OFF + name_bytes];
        buf[NAME_LEN_OFF..NAME_LEN_OFF + 4]
            .copy_from_slice(&(name_bytes as u32).to_le_bytes());
        for (i, &u) in u16s.iter().enumerate() {
            let off = NAME_OFF + i * 2;
            buf[off..off + 2].copy_from_slice(&u.to_le_bytes());
        }
        buf
    }

    /// Extract the FileName from a FILE_NAME_INFORMATION buffer using its
    /// embedded FileNameLength (lossy UTF-16 → String).
    fn read_fni_name(buf: &[u8]) -> String {
        assert!(buf.len() >= NAME_OFF + 4);
        let name_len = u32::from_le_bytes([
            buf[NAME_LEN_OFF], buf[NAME_LEN_OFF + 1],
            buf[NAME_LEN_OFF + 2], buf[NAME_LEN_OFF + 3],
        ]) as usize;
        assert!(NAME_OFF + name_len <= buf.len());
        let chars = name_len / 2;
        let mut out = String::with_capacity(chars);
        for i in 0..chars {
            let off = NAME_OFF + i * 2;
            let u = u16::from_le_bytes([buf[off], buf[off + 1]]);
            out.push(char::from_u32(u as u32).unwrap_or('?'));
        }
        out
    }

    const ROOT: &str = r"c:\users\me\.winrsbox\sbx\workdir";

    #[test]
    fn overlay_path_is_rewritten_to_virtual_relative() {
        // overlay volume-relative: \users\me\.winrsbox\sbx\workdir\d\proj\.git\HEAD
        let overlay_rel = r"\users\me\.winrsbox\sbx\workdir\d\proj\.git\HEAD";
        let buf = build_fni(overlay_rel);
        let rewritten = rewrite_file_name_information(&buf, ROOT)
            .expect("overlay path should be masked");
        let name = read_fni_name(&rewritten);
        assert_eq!(name, r"\proj\.git\HEAD");
        // No leak of the storage markers.
        assert!(!name.contains(".winrsbox"));
        assert!(!name.contains("workdir"));
    }

    #[test]
    fn non_overlay_path_is_left_untouched() {
        // A real system path on the same volume, NOT under sandbox_root.
        let buf = build_fni(r"\windows\system32\drivers\etc\hosts");
        let rewritten = rewrite_file_name_information(&buf, ROOT);
        assert!(rewritten.is_none(), "non-overlay path must passthrough");
    }

    #[test]
    fn overlay_root_drive_letter_from_sandbox_root() {
        // Even when the original FileName uppercases differ, the drive letter
        // is taken from sandbox_root and the prefix match is case-insensitive.
        let root = r"C:\Users\Me\.WinRsBox\SBX\Workdir";
        let overlay_rel = r"\Users\Me\.WinRsBox\SBX\Workdir\D\proj\file.txt";
        let buf = build_fni(overlay_rel);
        let rewritten = rewrite_file_name_information(&buf, root)
            .expect("case-insensitive overlay path should be masked");
        assert_eq!(read_fni_name(&rewritten), r"\proj\file.txt");
    }

    #[test]
    fn cross_drive_virtual_path_still_volume_relative() {
        // overlay on C:, virtual on D: — the rewrite returns the virtual
        // volume-relative path WITHOUT a drive letter (best-effort mask).
        let overlay_rel = r"\users\me\.winrsbox\sbx\workdir\d\proj\sub\f.txt";
        let buf = build_fni(overlay_rel);
        let rewritten = rewrite_file_name_information(&buf, ROOT)
            .expect("overlay path should be masked");
        assert_eq!(read_fni_name(&rewritten), r"\proj\sub\f.txt");
    }

    #[test]
    fn too_small_buffer_does_not_panic() {
        // Only 3 bytes — cannot even read FileNameLength.
        let buf = vec![0u8, 1, 2];
        assert!(rewrite_file_name_information(&buf, ROOT).is_none());
    }

    #[test]
    fn buffer_with_no_filename_bytes_does_not_panic() {
        // FileNameLength = 0 → nothing to rewrite.
        let mut buf = vec![0u8; NAME_OFF];
        buf[NAME_LEN_OFF..NAME_LEN_OFF + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(rewrite_file_name_information(&buf, ROOT).is_none());
    }

    #[test]
    fn truncated_name_length_does_not_panic() {
        // FileNameLength claims 100 bytes but the buffer only has 8.
        let mut buf = vec![0u8; NAME_OFF + 4];
        buf[NAME_LEN_OFF..NAME_LEN_OFF + 4].copy_from_slice(&100u32.to_le_bytes());
        assert!(rewrite_file_name_information(&buf, ROOT).is_none());
    }

    #[test]
    fn sandbox_root_prefix_lookalike_not_matched() {
        // `workdir2` shares a prefix string with `workdir` but is a different
        // component — must NOT be treated as inside the overlay.
        let overlay_rel = r"\users\me\.winrsbox\sbx\workdir2\d\proj\file.txt";
        let buf = build_fni(overlay_rel);
        assert!(rewrite_file_name_information(&buf, ROOT).is_none());
    }

    #[test]
    fn rewrite_zeros_slack_so_no_overlay_bytes_leak() {
        // Original name longer than the virtual one: the slack between the new
        // FileNameLength and the old one MUST be zeroed so consumers that
        // accidentally read past FileNameLength do not see overlay tail bytes.
        let overlay_rel = r"\users\me\.winrsbox\sbx\workdir\d\p.txt";
        let buf = build_fni(overlay_rel);
        let old_name_len = u32::from_le_bytes([
            buf[NAME_LEN_OFF], buf[NAME_LEN_OFF + 1],
            buf[NAME_LEN_OFF + 2], buf[NAME_LEN_OFF + 3],
        ]) as usize;
        let rewritten = rewrite_file_name_information(&buf, ROOT)
            .expect("overlay path should be masked");
        let new_name_len = u32::from_le_bytes([
            rewritten[NAME_LEN_OFF], rewritten[NAME_LEN_OFF + 1],
            rewritten[NAME_LEN_OFF + 2], rewritten[NAME_LEN_OFF + 3],
        ]) as usize;
        assert!(new_name_len < old_name_len, "new name must be shorter");
        // Every byte from new_name_len to old_name_len must be zero.
        for off in (NAME_OFF + new_name_len)..(NAME_OFF + old_name_len) {
            assert_eq!(rewritten[off], 0, "slack byte at offset {off} must be zero");
        }
        assert_eq!(read_fni_name(&rewritten), r"\p.txt");
    }

    #[test]
    fn empty_sandbox_root_passthrough() {
        let buf = build_fni(r"\users\me\.winrsbox\sbx\workdir\d\proj\file.txt");
        assert!(rewrite_file_name_information(&buf, "").is_none());
    }

    #[test]
    fn strip_drive_prefix_basic() {
        assert_eq!(strip_drive_prefix(r"d:\proj\file.txt"), r"\proj\file.txt");
        assert_eq!(strip_drive_prefix(r"D:\proj"), r"\proj");
        assert_eq!(strip_drive_prefix(r"\already\relative"), r"\already\relative");
    }
}
