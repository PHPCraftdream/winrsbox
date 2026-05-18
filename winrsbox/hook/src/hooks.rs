// Detour implementations for Nt* functions.
//
// Uses detour::GenericDetour (stable, no nightly) stored in OnceLock.
//
// Mode::Cow semantic (unified, no Redirect variant):
//   cow_from = None  → pure redirect (overlay already exists or read path)
//   cow_from = Some  → real CoW (copy original file before redirecting)

use std::sync::OnceLock;
// Use winapi's c_void to match signatures expected by winapi/ntapi functions.
use winapi::ctypes::c_void;

use detour::GenericDetour;
use ntapi::ntioapi::IO_STATUS_BLOCK;
use ntapi::winapi::shared::ntdef::{
    HANDLE, NTSTATUS, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
};
use ntapi::winapi::um::winnt::ACCESS_MASK;
use policy::{Decision, Mode};
use winapi::um::processthreadsapi::{GetCurrentProcessId, GetProcessId};

use crate::anti_rec;
use crate::cache::HookCache;
use crate::inject;

// ---------------------------------------------------------------------------
// Nt* function type aliases
// ---------------------------------------------------------------------------

type FnNtCreateFile = unsafe extern "system" fn(
    *mut HANDLE,            // FileHandle
    ACCESS_MASK,            // DesiredAccess
    *mut OBJECT_ATTRIBUTES, // ObjectAttributes
    *mut IO_STATUS_BLOCK,   // IoStatusBlock
    *mut i64,               // AllocationSize
    u32,                    // FileAttributes
    u32,                    // ShareAccess
    u32,                    // CreateDisposition
    u32,                    // CreateOptions
    *mut c_void,            // EaBuffer
    u32,                    // EaLength
) -> NTSTATUS;

type FnNtOpenFile = unsafe extern "system" fn(
    *mut HANDLE,            // FileHandle
    ACCESS_MASK,            // DesiredAccess
    *mut OBJECT_ATTRIBUTES, // ObjectAttributes
    *mut IO_STATUS_BLOCK,   // IoStatusBlock
    u32,                    // ShareAccess
    u32,                    // OpenOptions
) -> NTSTATUS;

type FnNtQueryAttributesFile = unsafe extern "system" fn(
    *mut OBJECT_ATTRIBUTES, // ObjectAttributes
    *mut c_void,            // FileInformation
) -> NTSTATUS;

type FnNtQueryFullAttributesFile = unsafe extern "system" fn(
    *mut OBJECT_ATTRIBUTES, // ObjectAttributes
    *mut c_void,            // FileInformation
) -> NTSTATUS;

type FnNtCreateUserProcess = unsafe extern "system" fn(
    *mut HANDLE,            // ProcessHandle
    *mut HANDLE,            // ThreadHandle
    ACCESS_MASK,            // ProcessDesiredAccess
    ACCESS_MASK,            // ThreadDesiredAccess
    *mut OBJECT_ATTRIBUTES, // ProcessObjectAttributes
    *mut OBJECT_ATTRIBUTES, // ThreadObjectAttributes
    u32,                    // ProcessFlags
    u32,                    // ThreadFlags
    *mut c_void,            // ProcessParameters
    *mut c_void,            // CreateInfo
    *mut c_void,            // AttributeList
) -> NTSTATUS;

// ---------------------------------------------------------------------------
// Detour storage
// ---------------------------------------------------------------------------

static HOOK_NT_CREATE_FILE: OnceLock<GenericDetour<FnNtCreateFile>> = OnceLock::new();
static HOOK_NT_OPEN_FILE: OnceLock<GenericDetour<FnNtOpenFile>> = OnceLock::new();
static HOOK_NT_QUERY_ATTRIBUTES_FILE: OnceLock<GenericDetour<FnNtQueryAttributesFile>> =
    OnceLock::new();
static HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE: OnceLock<GenericDetour<FnNtQueryFullAttributesFile>> =
    OnceLock::new();
static HOOK_NT_CREATE_USER_PROCESS: OnceLock<GenericDetour<FnNtCreateUserProcess>> =
    OnceLock::new();

// ---------------------------------------------------------------------------
// IPC / cache globals
// ---------------------------------------------------------------------------

static CACHE: OnceLock<HookCache> = OnceLock::new();

// Per-thread IPC connection. Each thread gets its own SyncClient so file-system
// calls don't serialize on a global mutex. The launcher pipe server handles
// each connection concurrently via spawn_blocking, giving real parallelism on
// multithreaded targets.
thread_local! {
    static IPC_CLIENT: std::cell::RefCell<Option<ipc::SyncClient>> =
        const { std::cell::RefCell::new(None) };
}

static PIPE_NAME: OnceLock<String> = OnceLock::new();
static DLL_PATH: OnceLock<String> = OnceLock::new();
static SANDBOX_CWD: OnceLock<String> = OnceLock::new();

fn cache() -> &'static HookCache {
    CACHE.get_or_init(HookCache::new)
}

fn decide(dos_path: &str, write: bool) -> Decision {
    if let Some(d) = cache().get_caseless(dos_path, write) {
        return d;
    }
    let lower = dos_path.to_ascii_lowercase();
    let d = ipc_decide(&lower, write);
    cache().insert(&lower, write, d.clone());
    d
}

fn ipc_decide(dos_lower: &str, write: bool) -> Decision {
    IPC_CLIENT.with_borrow_mut(|opt| {
        if opt.is_none() {
            if let Some(name) = PIPE_NAME.get() {
                // connect() has its own internal retry loop; if it still fails
                // leave opt = None so the next call retries afresh.
                *opt = ipc::SyncClient::connect(name).ok();
            }
        }
        if let Some(client) = opt.as_mut() {
            let req = ipc::Req::Decide {
                dos_path: dos_lower.to_owned(),
                write,
            };
            if let Ok(ipc::Resp::Decision(d)) = client.send(&req) {
                return d;
            }
        }
        Decision { mode: Mode::Passthrough, overlay: None, cow_from: None, mock_payload: None }
    })
}

fn ipc_record_overlay(orig: &str, overlay: &str) {
    IPC_CLIENT.with_borrow_mut(|opt| {
        if opt.is_none() {
            if let Some(name) = PIPE_NAME.get() {
                *opt = ipc::SyncClient::connect(name).ok();
            }
        }
        if let Some(client) = opt.as_mut() {
            let _ = client.send(&ipc::Req::RecordOverlay {
                orig: orig.to_owned(),
                overlay: overlay.to_owned(),
            });
        }
    });
}

fn ipc_register_child(pid: u32) {
    IPC_CLIENT.with_borrow_mut(|opt| {
        if opt.is_none() {
            if let Some(name) = PIPE_NAME.get() {
                *opt = ipc::SyncClient::connect(name).ok();
            }
        }
        if let Some(client) = opt.as_mut() {
            let _ = client.send(&ipc::Req::RegisterChild { pid });
        }
    });
}

fn ipc_log(level: ipc::LogLevel, msg: String) {
    // SAFETY: GetCurrentProcessId is always safe to call; it has no preconditions.
    let pid = unsafe { GetCurrentProcessId() };
    IPC_CLIENT.with_borrow_mut(|opt| {
        if opt.is_none() {
            if let Some(name) = PIPE_NAME.get() {
                *opt = ipc::SyncClient::connect(name).ok();
            }
        }
        if let Some(client) = opt.as_mut() {
            let _ = client.send(&ipc::Req::Log { pid, level, msg });
        }
    });
}

// ---------------------------------------------------------------------------
// IO_STATUS_BLOCK helper
// ---------------------------------------------------------------------------

/// Write the Status field (at offset 0) of an IO_STATUS_BLOCK.
///
/// # SAFETY
/// IO_STATUS_BLOCK.Status/Pointer union begins at offset 0 on all Windows
/// x64 ABIs. Writing an i32 (NTSTATUS) to offset 0 is always correct.
unsafe fn set_io_status(block: *mut IO_STATUS_BLOCK, status: NTSTATUS) {
    if !block.is_null() {
        std::ptr::write(block as *mut i32, status);
    }
}

// ---------------------------------------------------------------------------
// NT path buffer builder
//
// Returns a Vec<u16> for `\??\<overlay_dos_path>\0`.
// The Vec MUST outlive any UNICODE_STRING / OBJECT_ATTRIBUTES that borrows
// its data pointer.
// ---------------------------------------------------------------------------
fn make_overlay_nt_buf(overlay_dos: &str) -> Vec<u16> {
    policy::path::dos_to_nt(overlay_dos)
}

// ---------------------------------------------------------------------------
// Write-access detection
// ---------------------------------------------------------------------------

pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
pub const DELETE: u32 = 0x0001_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;

pub const FILE_CREATE: u32 = 0x0000_0002;
pub const FILE_OVERWRITE: u32 = 0x0000_0004;
pub const FILE_OVERWRITE_IF: u32 = 0x0000_0005;
pub const FILE_SUPERSEDE: u32 = 0x0000_0000;

pub fn is_write_access(desired: ACCESS_MASK, disposition: u32) -> bool {
    let write_bits =
        GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER;
    desired & write_bits != 0
        || matches!(disposition, FILE_CREATE | FILE_OVERWRITE | FILE_OVERWRITE_IF | FILE_SUPERSEDE)
}

// ---------------------------------------------------------------------------
// Path extraction
// ---------------------------------------------------------------------------

/// Extract a DOS path string from an OBJECT_ATTRIBUTES.
///
/// # SAFETY
/// `attrs` and its ObjectName must be valid for reads for the duration of the
/// call (guaranteed by NT calling convention for hook parameters).
unsafe fn extract_dos_path(attrs: *const OBJECT_ATTRIBUTES) -> Option<String> {
    if attrs.is_null() {
        return None;
    }
    let obj = &*attrs;
    if obj.ObjectName.is_null() {
        return None;
    }
    let ustr = &*obj.ObjectName;
    let char_count = (ustr.Length / 2) as usize;
    if char_count == 0 {
        return None;
    }
    // SAFETY: Buffer is valid for at least Length bytes per NT UNICODE_STRING contract.
    let name_slice = std::slice::from_raw_parts(ustr.Buffer, char_count);

    if !obj.RootDirectory.is_null() {
        let base = inject::resolve_handle_path(obj.RootDirectory)?;
        let mut full: Vec<u16> = base;
        full.push(b'\\' as u16);
        full.extend_from_slice(name_slice);
        return policy::path::nt_to_dos(&full);
    }

    policy::path::nt_to_dos(name_slice)
}

// ---------------------------------------------------------------------------
// CoW helper
// ---------------------------------------------------------------------------

fn prepare_overlay(decision: &Decision) -> Option<String> {
    let overlay_path = decision.overlay.as_ref()?;
    let overlay_dos = overlay_path.to_string_lossy().into_owned();

    if let Some(parent) = overlay_path.parent() {
        // IN_HOOK is true on this thread; filesystem calls here will see IN_HOOK=true
        // in the hook and call the original immediately — no recursion.
        let _ = std::fs::create_dir_all(parent);
    }

    if let Some(ref src) = decision.cow_from {
        if !overlay_path.exists() {
            let _ = std::fs::copy(src, overlay_path);
        }
    }

    Some(overlay_dos)
}

// ---------------------------------------------------------------------------
// STATUS codes
// ---------------------------------------------------------------------------

const STATUS_ACCESS_DENIED: NTSTATUS = 0xC000_0022_u32 as NTSTATUS;

// ---------------------------------------------------------------------------
// Hook implementations
// ---------------------------------------------------------------------------

unsafe extern "system" fn hook_nt_create_file(
    file_handle: *mut HANDLE,
    desired_access: ACCESS_MASK,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    io_status_block: *mut IO_STATUS_BLOCK,
    allocation_size: *mut i64,
    file_attributes: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    ea_buffer: *mut c_void,
    ea_length: u32,
) -> NTSTATUS {
    macro_rules! call_original {
        () => {
            HOOK_NT_CREATE_FILE.get().unwrap().call(
                file_handle, desired_access, object_attributes, io_status_block,
                allocation_size, file_attributes, share_access, create_disposition,
                create_options, ea_buffer, ea_length,
            )
        };
    }

    let Some(_guard) = anti_rec::enter() else {
        return call_original!();
    };

    // SAFETY: object_attributes valid per NT calling convention for the call duration.
    let Some(dos) = extract_dos_path(object_attributes as *const _) else {
        return call_original!();
    };

    let write = is_write_access(desired_access, create_disposition);
    let decision = decide(&dos, write);

    match decision.mode {
        Mode::Passthrough => call_original!(),
        Mode::Deny => {
            if !file_handle.is_null() {
                *file_handle = std::ptr::null_mut();
            }
            // SAFETY: set_io_status writes offset 0 of IO_STATUS_BLOCK union.
            set_io_status(io_status_block, STATUS_ACCESS_DENIED);
            STATUS_ACCESS_DENIED
        }
        Mode::Cow => {
            let Some(overlay_dos) = prepare_overlay(&decision) else {
                return call_original!();
            };
            let lower = dos.to_lowercase();
            ipc_record_overlay(&lower, &overlay_dos);
            cache().invalidate(&lower);

            // SCOPE: nt_buf must outlive new_ustr and new_attrs.
            let nt_buf = make_overlay_nt_buf(&overlay_dos);
            let char_count = nt_buf.len().saturating_sub(1);
            let mut new_ustr = UNICODE_STRING {
                Length: (char_count * 2) as u16,
                MaximumLength: (nt_buf.len() * 2) as u16,
                Buffer: nt_buf.as_ptr() as *mut u16,
            };
            // SAFETY: object_attributes is non-null (checked above via extract_dos_path).
            let orig = &*object_attributes;
            let mut new_attrs = OBJECT_ATTRIBUTES {
                Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
                RootDirectory: std::ptr::null_mut(),
                ObjectName: &mut new_ustr,
                Attributes: orig.Attributes | OBJ_CASE_INSENSITIVE,
                SecurityDescriptor: orig.SecurityDescriptor,
                SecurityQualityOfService: orig.SecurityQualityOfService,
            };
            HOOK_NT_CREATE_FILE.get().unwrap().call(
                file_handle, desired_access, &mut new_attrs, io_status_block,
                allocation_size, file_attributes, share_access, create_disposition,
                create_options, ea_buffer, ea_length,
            )
        }
        Mode::Mock => {
            let Some(payload) = decision.mock_payload else {
                return call_original!();
            };
            let Some(ref overlay_path) = decision.overlay else {
                return call_original!();
            };
            if let Some(parent) = overlay_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(overlay_path, &payload);
            let overlay_dos = overlay_path.to_string_lossy().into_owned();

            // SCOPE: nt_buf must outlive new_ustr and new_attrs.
            let nt_buf = make_overlay_nt_buf(&overlay_dos);
            let char_count = nt_buf.len().saturating_sub(1);
            let mut new_ustr = UNICODE_STRING {
                Length: (char_count * 2) as u16,
                MaximumLength: (nt_buf.len() * 2) as u16,
                Buffer: nt_buf.as_ptr() as *mut u16,
            };
            // SAFETY: object_attributes is non-null.
            let orig = &*object_attributes;
            let mut new_attrs = OBJECT_ATTRIBUTES {
                Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
                RootDirectory: std::ptr::null_mut(),
                ObjectName: &mut new_ustr,
                Attributes: orig.Attributes | OBJ_CASE_INSENSITIVE,
                SecurityDescriptor: orig.SecurityDescriptor,
                // SecurityQualityOfService must be null for file objects; copying
                // it from orig causes STATUS_INVALID_PARAMETER on NT file opens.
                SecurityQualityOfService: std::ptr::null_mut(),
            };
            HOOK_NT_CREATE_FILE.get().unwrap().call(
                file_handle, desired_access, &mut new_attrs, io_status_block,
                allocation_size, file_attributes, share_access,
                create_disposition, create_options, ea_buffer, ea_length,
            )
        }
    }
}

unsafe extern "system" fn hook_nt_open_file(
    file_handle: *mut HANDLE,
    desired_access: ACCESS_MASK,
    object_attributes: *mut OBJECT_ATTRIBUTES,
    io_status_block: *mut IO_STATUS_BLOCK,
    share_access: u32,
    open_options: u32,
) -> NTSTATUS {
    macro_rules! call_original {
        () => {
            HOOK_NT_OPEN_FILE.get().unwrap().call(
                file_handle, desired_access, object_attributes,
                io_status_block, share_access, open_options,
            )
        };
    }

    let Some(_guard) = anti_rec::enter() else {
        return call_original!();
    };

    // SAFETY: object_attributes valid per NT calling convention.
    let Some(dos) = extract_dos_path(object_attributes as *const _) else {
        return call_original!();
    };

    let write_bits =
        GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | WRITE_DAC | WRITE_OWNER;
    let write = desired_access & write_bits != 0;
    let decision = decide(&dos, write);

    match decision.mode {
        Mode::Passthrough => call_original!(),
        Mode::Deny => {
            if !file_handle.is_null() {
                *file_handle = std::ptr::null_mut();
            }
            // SAFETY: set_io_status writes offset 0 of IO_STATUS_BLOCK union.
            set_io_status(io_status_block, STATUS_ACCESS_DENIED);
            STATUS_ACCESS_DENIED
        }
        Mode::Cow => {
            let Some(overlay_dos) = prepare_overlay(&decision) else {
                return call_original!();
            };
            let lower = dos.to_lowercase();
            ipc_record_overlay(&lower, &overlay_dos);
            cache().invalidate(&lower);

            // SCOPE: nt_buf must outlive new_ustr and new_attrs.
            let nt_buf = make_overlay_nt_buf(&overlay_dos);
            let char_count = nt_buf.len().saturating_sub(1);
            let mut new_ustr = UNICODE_STRING {
                Length: (char_count * 2) as u16,
                MaximumLength: (nt_buf.len() * 2) as u16,
                Buffer: nt_buf.as_ptr() as *mut u16,
            };
            // SAFETY: object_attributes is non-null.
            let orig = &*object_attributes;
            let mut new_attrs = OBJECT_ATTRIBUTES {
                Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
                RootDirectory: std::ptr::null_mut(),
                ObjectName: &mut new_ustr,
                Attributes: orig.Attributes | OBJ_CASE_INSENSITIVE,
                SecurityDescriptor: orig.SecurityDescriptor,
                SecurityQualityOfService: orig.SecurityQualityOfService,
            };
            HOOK_NT_OPEN_FILE.get().unwrap().call(
                file_handle, desired_access, &mut new_attrs,
                io_status_block, share_access, open_options,
            )
        }
        Mode::Mock => {
            let Some(payload) = decision.mock_payload else {
                return call_original!();
            };
            let Some(ref overlay_path) = decision.overlay else {
                return call_original!();
            };
            if let Some(parent) = overlay_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(overlay_path, &payload);
            let overlay_dos = overlay_path.to_string_lossy().into_owned();

            // SCOPE: nt_buf must outlive new_ustr and new_attrs.
            let nt_buf = make_overlay_nt_buf(&overlay_dos);
            let char_count = nt_buf.len().saturating_sub(1);
            let mut new_ustr = UNICODE_STRING {
                Length: (char_count * 2) as u16,
                MaximumLength: (nt_buf.len() * 2) as u16,
                Buffer: nt_buf.as_ptr() as *mut u16,
            };
            // SAFETY: object_attributes is non-null.
            let orig = &*object_attributes;
            let mut new_attrs = OBJECT_ATTRIBUTES {
                Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
                RootDirectory: std::ptr::null_mut(),
                ObjectName: &mut new_ustr,
                Attributes: orig.Attributes | OBJ_CASE_INSENSITIVE,
                SecurityDescriptor: orig.SecurityDescriptor,
                // SecurityQualityOfService must be null for file objects.
                SecurityQualityOfService: std::ptr::null_mut(),
            };
            HOOK_NT_OPEN_FILE.get().unwrap().call(
                file_handle, desired_access, &mut new_attrs,
                io_status_block, share_access, open_options,
            )
        }
    }
}

unsafe extern "system" fn hook_nt_query_attributes_file(
    object_attributes: *mut OBJECT_ATTRIBUTES,
    file_information: *mut c_void,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return HOOK_NT_QUERY_ATTRIBUTES_FILE
            .get()
            .unwrap()
            .call(object_attributes, file_information);
    };

    // SAFETY: object_attributes valid per NT calling convention.
    let Some(dos) = extract_dos_path(object_attributes as *const _) else {
        return HOOK_NT_QUERY_ATTRIBUTES_FILE
            .get()
            .unwrap()
            .call(object_attributes, file_information);
    };

    let decision = decide(&dos, false);
    match decision.mode {
        Mode::Passthrough => HOOK_NT_QUERY_ATTRIBUTES_FILE
            .get()
            .unwrap()
            .call(object_attributes, file_information),
        Mode::Deny => STATUS_ACCESS_DENIED,
        Mode::Mock => {
            let Some(ref overlay_path) = decision.overlay else {
                return HOOK_NT_QUERY_ATTRIBUTES_FILE
                    .get()
                    .unwrap()
                    .call(object_attributes, file_information);
            };
            // If overlay missing, materialize mock payload first so the
            // redirected query observes the mocked file instead of ENOENT.
            if !overlay_path.exists() {
                if let Some(ref payload) = decision.mock_payload {
                    if let Some(parent) = overlay_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::write(overlay_path, payload);
                } else {
                    return HOOK_NT_QUERY_ATTRIBUTES_FILE
                        .get()
                        .unwrap()
                        .call(object_attributes, file_information);
                }
            }
            let overlay_dos = overlay_path.to_string_lossy().into_owned();
            // SCOPE: nt_buf must outlive new_ustr and new_attrs.
            let nt_buf = make_overlay_nt_buf(&overlay_dos);
            let char_count = nt_buf.len().saturating_sub(1);
            let mut new_ustr = UNICODE_STRING {
                Length: (char_count * 2) as u16,
                MaximumLength: (nt_buf.len() * 2) as u16,
                Buffer: nt_buf.as_ptr() as *mut u16,
            };
            // SAFETY: object_attributes is non-null.
            let orig = &*object_attributes;
            let mut new_attrs = OBJECT_ATTRIBUTES {
                Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
                RootDirectory: std::ptr::null_mut(),
                ObjectName: &mut new_ustr,
                Attributes: orig.Attributes | OBJ_CASE_INSENSITIVE,
                SecurityDescriptor: orig.SecurityDescriptor,
                SecurityQualityOfService: orig.SecurityQualityOfService,
            };
            HOOK_NT_QUERY_ATTRIBUTES_FILE
                .get()
                .unwrap()
                .call(&mut new_attrs, file_information)
        }
        Mode::Cow => {
            let Some(ref overlay_path) = decision.overlay else {
                return HOOK_NT_QUERY_ATTRIBUTES_FILE
                    .get()
                    .unwrap()
                    .call(object_attributes, file_information);
            };
            if !overlay_path.exists() {
                return HOOK_NT_QUERY_ATTRIBUTES_FILE
                    .get()
                    .unwrap()
                    .call(object_attributes, file_information);
            }
            let overlay_dos = overlay_path.to_string_lossy().into_owned();
            // SCOPE: nt_buf must outlive new_ustr and new_attrs.
            let nt_buf = make_overlay_nt_buf(&overlay_dos);
            let char_count = nt_buf.len().saturating_sub(1);
            let mut new_ustr = UNICODE_STRING {
                Length: (char_count * 2) as u16,
                MaximumLength: (nt_buf.len() * 2) as u16,
                Buffer: nt_buf.as_ptr() as *mut u16,
            };
            // SAFETY: object_attributes is non-null.
            let orig = &*object_attributes;
            let mut new_attrs = OBJECT_ATTRIBUTES {
                Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
                RootDirectory: std::ptr::null_mut(),
                ObjectName: &mut new_ustr,
                Attributes: orig.Attributes | OBJ_CASE_INSENSITIVE,
                SecurityDescriptor: orig.SecurityDescriptor,
                SecurityQualityOfService: orig.SecurityQualityOfService,
            };
            HOOK_NT_QUERY_ATTRIBUTES_FILE
                .get()
                .unwrap()
                .call(&mut new_attrs, file_information)
        }
    }
}

unsafe extern "system" fn hook_nt_query_full_attributes_file(
    object_attributes: *mut OBJECT_ATTRIBUTES,
    file_information: *mut c_void,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE
            .get()
            .unwrap()
            .call(object_attributes, file_information);
    };

    // SAFETY: object_attributes valid per NT calling convention.
    let Some(dos) = extract_dos_path(object_attributes as *const _) else {
        return HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE
            .get()
            .unwrap()
            .call(object_attributes, file_information);
    };

    let decision = decide(&dos, false);
    match decision.mode {
        Mode::Passthrough => HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE
            .get()
            .unwrap()
            .call(object_attributes, file_information),
        Mode::Deny => STATUS_ACCESS_DENIED,
        Mode::Mock => {
            let Some(ref overlay_path) = decision.overlay else {
                return HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE
                    .get()
                    .unwrap()
                    .call(object_attributes, file_information);
            };
            // If overlay missing, materialize mock payload first so the
            // redirected query observes the mocked file instead of ENOENT.
            if !overlay_path.exists() {
                if let Some(ref payload) = decision.mock_payload {
                    if let Some(parent) = overlay_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::write(overlay_path, payload);
                } else {
                    return HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE
                        .get()
                        .unwrap()
                        .call(object_attributes, file_information);
                }
            }
            let overlay_dos = overlay_path.to_string_lossy().into_owned();
            // SCOPE: nt_buf must outlive new_ustr and new_attrs.
            let nt_buf = make_overlay_nt_buf(&overlay_dos);
            let char_count = nt_buf.len().saturating_sub(1);
            let mut new_ustr = UNICODE_STRING {
                Length: (char_count * 2) as u16,
                MaximumLength: (nt_buf.len() * 2) as u16,
                Buffer: nt_buf.as_ptr() as *mut u16,
            };
            // SAFETY: object_attributes is non-null.
            let orig = &*object_attributes;
            let mut new_attrs = OBJECT_ATTRIBUTES {
                Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
                RootDirectory: std::ptr::null_mut(),
                ObjectName: &mut new_ustr,
                Attributes: orig.Attributes | OBJ_CASE_INSENSITIVE,
                SecurityDescriptor: orig.SecurityDescriptor,
                SecurityQualityOfService: orig.SecurityQualityOfService,
            };
            HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE
                .get()
                .unwrap()
                .call(&mut new_attrs, file_information)
        }
        Mode::Cow => {
            let Some(ref overlay_path) = decision.overlay else {
                return HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE
                    .get()
                    .unwrap()
                    .call(object_attributes, file_information);
            };
            if !overlay_path.exists() {
                return HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE
                    .get()
                    .unwrap()
                    .call(object_attributes, file_information);
            }
            let overlay_dos = overlay_path.to_string_lossy().into_owned();
            // SCOPE: nt_buf must outlive new_ustr and new_attrs.
            let nt_buf = make_overlay_nt_buf(&overlay_dos);
            let char_count = nt_buf.len().saturating_sub(1);
            let mut new_ustr = UNICODE_STRING {
                Length: (char_count * 2) as u16,
                MaximumLength: (nt_buf.len() * 2) as u16,
                Buffer: nt_buf.as_ptr() as *mut u16,
            };
            // SAFETY: object_attributes is non-null.
            let orig = &*object_attributes;
            let mut new_attrs = OBJECT_ATTRIBUTES {
                Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
                RootDirectory: std::ptr::null_mut(),
                ObjectName: &mut new_ustr,
                Attributes: orig.Attributes | OBJ_CASE_INSENSITIVE,
                SecurityDescriptor: orig.SecurityDescriptor,
                SecurityQualityOfService: orig.SecurityQualityOfService,
            };
            HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE
                .get()
                .unwrap()
                .call(&mut new_attrs, file_information)
        }
    }
}

const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u32 = 0x0000_0001;

unsafe extern "system" fn hook_nt_create_user_process(
    process_handle: *mut HANDLE,
    thread_handle: *mut HANDLE,
    process_desired_access: ACCESS_MASK,
    thread_desired_access: ACCESS_MASK,
    process_object_attributes: *mut OBJECT_ATTRIBUTES,
    thread_object_attributes: *mut OBJECT_ATTRIBUTES,
    process_flags: u32,
    thread_flags: u32,
    process_parameters: *mut c_void,
    create_info: *mut c_void,
    attribute_list: *mut c_void,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return HOOK_NT_CREATE_USER_PROCESS.get().unwrap().call(
            process_handle, thread_handle,
            process_desired_access, thread_desired_access,
            process_object_attributes, thread_object_attributes,
            process_flags, thread_flags,
            process_parameters, create_info, attribute_list,
        );
    };

    // Force the child to start suspended so we can inject before it runs.
    let forced_flags = thread_flags | THREAD_CREATE_FLAGS_CREATE_SUSPENDED;
    let originally_suspended = (thread_flags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED) != 0;

    let status = HOOK_NT_CREATE_USER_PROCESS.get().unwrap().call(
        process_handle, thread_handle,
        process_desired_access, thread_desired_access,
        process_object_attributes, thread_object_attributes,
        process_flags, forced_flags,
        process_parameters, create_info, attribute_list,
    );

    if status < 0 {
        return status;
    }

    let proc_h = if process_handle.is_null() { return status; } else { *process_handle };
    let thr_h = if thread_handle.is_null() { return status; } else { *thread_handle };

    if proc_h.is_null() || thr_h.is_null() {
        return status;
    }

    // Register with launcher for process-tree tracking.
    // SAFETY: proc_h is a valid process handle returned by NtCreateUserProcess.
    let child_pid = GetProcessId(proc_h);
    if child_pid != 0 {
        ipc_register_child(child_pid);
    }

    // Inject hook.dll via APC. If injection fails the child process ALREADY
    // exists (suspended, no user code executed yet) and would escape the
    // sandbox once resumed. Terminate it before resume — fail closed.
    let mut inject_failed = false;
    if let Some(dll_path) = DLL_PATH.get() {
        if let Err(e) = inject::inject_via_apc(proc_h, thr_h, dll_path) {
            ipc_log(
                ipc::LogLevel::Error,
                format!("APC inject failed pid={child_pid}: {e}; terminating sandbox-escape candidate"),
            );
            // SAFETY: proc_h is the valid PROCESS handle returned moments ago
            // by NtCreateUserProcess; TerminateProcess never blocks. Exit code 1
            // signals "killed by sandbox" to anyone waiting on the process.
            unsafe { winapi::um::processthreadsapi::TerminateProcess(proc_h, 1) };
            inject_failed = true;
        }
    }

    // Resume if the caller did not want a suspended thread — but skip if we
    // just killed the child; there is nothing to resume in a dead process and
    // ResumeThread would only return an error.
    if !originally_suspended && !inject_failed {
        let mut suspend_count: u32 = 0;
        // SAFETY: thr_h is a valid thread handle; NtResumeThread is always present.
        ntapi::ntpsapi::NtResumeThread(thr_h, &mut suspend_count);
    }

    status
}

// ---------------------------------------------------------------------------
// Resolve an export from ntdll.dll by name.
// ---------------------------------------------------------------------------

unsafe fn ntdll_export(name: &[u8]) -> Option<*const ()> {
    use winapi::um::libloaderapi::{GetModuleHandleW, GetProcAddress};
    let ntdll_w: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    // SAFETY: ntdll_w is null-terminated UTF-16 name of a module always present.
    let hmod = GetModuleHandleW(ntdll_w.as_ptr());
    if hmod.is_null() {
        return None;
    }
    // SAFETY: name is a valid null-terminated ASCII byte slice.
    let p = GetProcAddress(hmod, name.as_ptr() as *const i8);
    if p.is_null() { None } else { Some(p as *const ()) }
}

// ---------------------------------------------------------------------------
// Public install / uninstall
// ---------------------------------------------------------------------------

/// Install all Nt* detours.
///
/// # SAFETY
/// Must be called at most once, from DllMain(DLL_PROCESS_ATTACH), with the
/// loader lock held. Only Win32 APIs safe in DllMain are used here
/// (GetModuleHandleW, GetProcAddress, VirtualAlloc via detour internals).
pub unsafe fn install_hooks() -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(pipe) = std::env::var("FS_SANDBOX_PIPE") {
        let _ = PIPE_NAME.set(pipe);
    }
    if let Ok(dll) = std::env::var("FS_SANDBOX_DLL") {
        let _ = DLL_PATH.set(dll);
    }
    if let Ok(cwd) = std::env::var("FS_SANDBOX_CWD") {
        let _ = SANDBOX_CWD.set(cwd.clone());
        // Override the process CWD to the sandbox root. This runs before any
        // user-mode entry point code, so the process sees the right directory
        // from the first os.Getwd() / GetCurrentDirectory call.
        // SetCurrentDirectoryW is safe to call from DllMain (pure RtlSetCurrentDirectory_U).
        let wide: Vec<u16> = cwd.encode_utf16().chain(Some(0)).collect();
        // SAFETY: wide is a valid null-terminated UTF-16 path string.
        unsafe { winapi::um::processenv::SetCurrentDirectoryW(wide.as_ptr()) };
    }

    macro_rules! install {
        ($lock:expr, $sym:literal, $hook_fn:expr, $fn_ty:ty) => {{
            let addr = ntdll_export($sym.as_bytes())
                .ok_or_else(|| format!("ntdll export not found: {}", $sym))?;
            // SAFETY: addr is the real ntdll export matching the FnNt* type alias.
            let target: $fn_ty = std::mem::transmute(addr as usize);
            let hook_ptr: $fn_ty = $hook_fn;
            let detour = GenericDetour::<$fn_ty>::new(target, hook_ptr)
                .map_err(|e| format!("detour init {}: {:?}", $sym, e))?;
            // Populate OnceLock BEFORE enabling so the hook never observes an
            // empty OnceLock: hook_* calls $lock.get().unwrap(), which would
            // panic if the hook fired in the window between enable and set.
            $lock.set(detour).ok();
            $lock.get()
                .expect("set above")
                .enable()
                .map_err(|e| format!("detour enable {}: {:?}", $sym, e))?;
        }};
    }

    install!(HOOK_NT_CREATE_FILE,              "NtCreateFile\0",              hook_nt_create_file,              FnNtCreateFile);
    install!(HOOK_NT_OPEN_FILE,                "NtOpenFile\0",                hook_nt_open_file,                FnNtOpenFile);
    install!(HOOK_NT_QUERY_ATTRIBUTES_FILE,    "NtQueryAttributesFile\0",     hook_nt_query_attributes_file,    FnNtQueryAttributesFile);
    install!(HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE, "NtQueryFullAttributesFile\0", hook_nt_query_full_attributes_file, FnNtQueryFullAttributesFile);
    install!(HOOK_NT_CREATE_USER_PROCESS,      "NtCreateUserProcess\0",       hook_nt_create_user_process,      FnNtCreateUserProcess);

    Ok(())
}

/// Disable all detours. Called from DllMain(DLL_PROCESS_DETACH).
///
/// # SAFETY
/// Must be called on DLL_PROCESS_DETACH only. Errors are ignored because
/// the process is tearing down.
pub unsafe fn uninstall_hooks() {
    if let Some(h) = HOOK_NT_CREATE_FILE.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_NT_OPEN_FILE.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_NT_QUERY_ATTRIBUTES_FILE.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE.get() { let _ = h.disable(); }
    if let Some(h) = HOOK_NT_CREATE_USER_PROCESS.get() { let _ = h.disable(); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_access_flags() {
        assert!(is_write_access(GENERIC_WRITE, 0));
        assert!(is_write_access(FILE_APPEND_DATA, 0));
        assert!(is_write_access(DELETE, 0));
        assert!(is_write_access(0, FILE_CREATE));
        assert!(is_write_access(0, FILE_OVERWRITE_IF));
        assert!(is_write_access(0, FILE_SUPERSEDE));
        assert!(!is_write_access(0, 1)); // FILE_OPEN
    }
}
