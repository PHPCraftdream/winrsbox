// escape_ntfs_ea — NtCreateFile that supplies a non-empty NTFS
// Extended-Attribute (EA) buffer. Drives the EA-defence policy (audit H-S3):
//
//   - On a CoW destination (out-of-project): the EA is harmless (trapped in
//     the overlay), so the create must SUCCEED.
//   - On a Passthrough destination (project_root, real disk): the EA is the
//     BlackLotus-class covert-storage vector, so the create must be DENIED
//     (STATUS_ACCESS_DENIED).
//
// The memory_guard test `ntfs_ea_blocked_on_passthrough_allowed_on_cow` runs
// this payload against both a CoW path (%TEMP%) and a Passthrough path
// (project_root) and asserts those two outcomes. This pins the fix that moved
// the EA block to AFTER the policy decision (was firing unconditionally and
// breaking extraction of binaries like uv.exe that carry a download EA).
//
// Exit codes:
//   0 — file created with EA (EA policy allowed it).
//   5 — STATUS_ACCESS_DENIED (EA policy blocked it).
//   2 — payload setup / usage error.

use std::os::windows::ffi::OsStrExt;

fn main() {
    let target_dos = match std::env::args().nth(1) {
        Some(p) if !p.is_empty() => p,
        _ => {
            eprintln!("[escape_ntfs_ea] usage: escape_ntfs_ea <dos_path>");
            std::process::exit(2);
        }
    };
    eprintln!("[escape_ntfs_ea] target={target_dos}");

    // Build the NT object name `\??\<target_dos>`.
    let nt_name: Vec<u16> = std::ffi::OsStr::new(&format!("\\??\\{target_dos}"))
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // FILE_FULL_EA_INFORMATION (single entry, no chaining):
    //   ULONG  NextEntryOffset;   // 0
    //   UCHAR  Flags;             // 0
    //   UCHAR  EaNameLength;      // strlen(name)
    //   USHORT EaValueLength;     // strlen(value)
    //   CHAR   EaName[1];         // name, NUL, value
    let ea_name = b"winrsbox";
    let ea_value = b"ea-test";
    let header = 4 + 1 + 1 + 2; // NextEntryOffset + Flags + EaNameLength + EaValueLength
    let name_with_nul = ea_name.len() + 1; // name + NUL terminator
    let ea_len = header + name_with_nul + ea_value.len();
    let mut ea: Vec<u8> = Vec::with_capacity(ea_len);
    ea.extend_from_slice(&0u32.to_le_bytes()); // NextEntryOffset = 0
    ea.push(0); // Flags
    ea.push(ea_name.len() as u8); // EaNameLength
    ea.extend_from_slice(&(ea_value.len() as u16).to_le_bytes()); // EaValueLength
    ea.extend_from_slice(ea_name);
    ea.push(0); // NUL after name
    ea.extend_from_slice(ea_value);
    debug_assert_eq!(ea.len(), ea_len);

    unsafe {
        let mut ustr = ntapi::winapi::shared::ntdef::UNICODE_STRING {
            Length: ((nt_name.len() - 1) * 2) as u16,
            MaximumLength: (nt_name.len() * 2) as u16,
            Buffer: nt_name.as_ptr() as *mut u16,
        };
        let mut oa = ntapi::winapi::shared::ntdef::OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<ntapi::winapi::shared::ntdef::OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: &mut ustr,
            Attributes: 0x40, // OBJ_CASE_INSENSITIVE
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let mut handle: ntapi::winapi::shared::ntdef::HANDLE = std::ptr::null_mut();
        let mut iosb: ntapi::ntioapi::IO_STATUS_BLOCK = std::mem::zeroed();

        // GENERIC_WRITE | SYNCHRONIZE; FILE_CREATE (new file); the EA buffer.
        let status = ntapi::ntioapi::NtCreateFile(
            &mut handle,
            0x40000000 | 0x00100000, // GENERIC_WRITE | SYNCHRONIZE
            &mut oa,
            &mut iosb,
            std::ptr::null_mut(),
            0,
            0x07, // FILE_SHARE_READ | WRITE | DELETE
            2,    // FILE_CREATE
            0x20, // FILE_SYNCHRONOUS_IO_NONALERT
            ea.as_mut_ptr() as *mut _,
            ea_len as u32,
        );

        if status >= 0 {
            eprintln!("[escape_ntfs_ea] created with EA — allowed");
            winapi::um::handleapi::CloseHandle(handle);
            std::process::exit(0);
        }
        if status as u32 == 0xC0000022 {
            eprintln!("[escape_ntfs_ea] blocked: STATUS_ACCESS_DENIED");
            std::process::exit(5);
        }
        eprintln!("[escape_ntfs_ea] other status=0x{status:08x}");
        std::process::exit(1);
    }
}
