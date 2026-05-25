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

use detour2::GenericDetour;
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
    static HELLO_SENT: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

static PIPE_NAME: OnceLock<String> = OnceLock::new();
static DLL_PATH: OnceLock<String> = OnceLock::new();
static SANDBOX_CWD: OnceLock<String> = OnceLock::new();
static TRACE_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn is_trace() -> bool {
    TRACE_ENABLED.load(std::sync::atomic::Ordering::Relaxed)
}

fn cache() -> &'static HookCache {
    CACHE.get_or_init(HookCache::new)
}

fn decide(dos_path: &str, write: bool) -> Decision {
    // dos_path is already lowercase from nt_to_dos_lower in extract_dos_path
    if let Some(d) = cache().get_caseless(dos_path, write) {
        return d;
    }
    let d = ipc_decide(dos_path, write);
    cache().insert(dos_path, write, d.clone());
    d
}

fn ensure_ipc_and<R>(f: impl FnOnce(&mut Option<ipc::SyncClient>) -> R) -> Option<R> {
    let mut sent = false;
    let result = IPC_CLIENT.with_borrow_mut(|opt| {
        if opt.is_none() {
            if let Some(name) = PIPE_NAME.get() {
                *opt = ipc::SyncClient::connect(name).ok();
                // Send Hello on first connection
                if opt.is_some() && !HELLO_SENT.get() {
                    let pid = unsafe { GetCurrentProcessId() };
                    let exe = get_own_exe_path();
                    let _ = opt.as_mut().unwrap().send(&ipc::Req::Hello {
                        pid,
                        exe_path: exe,
                    });
                    sent = true;
                }
            }
        }
        if opt.is_some() {
            Some(f(opt))
        } else {
            None
        }
    });
    if sent {
        HELLO_SENT.set(true);
        crate::inject_guard::arm();
    }
    result
}

fn ipc_decide(dos_lower: &str, write: bool) -> Decision {
    ensure_ipc_and(|opt| {
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
    }).unwrap_or(Decision { mode: Mode::Passthrough, overlay: None, cow_from: None, mock_payload: None })
}

fn ipc_record_overlay(orig: &str, overlay: &str) {
    let _ = ensure_ipc_and(|opt| {
        if let Some(client) = opt.as_mut() {
            let _ = client.send(&ipc::Req::RecordOverlay {
                orig: orig.to_owned(),
                overlay: overlay.to_owned(),
            });
        }
    });
}

fn ipc_register_child(pid: u32) {
    let _ = ensure_ipc_and(|opt| {
        if let Some(client) = opt.as_mut() {
            let _ = client.send(&ipc::Req::RegisterChild { pid });
        }
    });
}

fn ipc_spawned_child(parent_pid: u32, child_pid: u32, child_exe: String) {
    let _ = ensure_ipc_and(|opt| {
        if let Some(client) = opt.as_mut() {
            let _ = client.send(&ipc::Req::SpawnedChild {
                parent_pid,
                child_pid,
                child_exe,
            });
        }
    });
}

/// Send a request and return the Resp if the pipe is connected.
/// Used by reg_hooks for RegDecide, net_hooks for NetDecide, etc.
pub(crate) fn ipc_send_and_recv(req: ipc::Req) -> Option<ipc::Resp> {
    ensure_ipc_and(|opt| {
        if let Some(client) = opt.as_mut() {
            return client.send(&req).ok();
        }
        None
    }).flatten()
}

pub(crate) fn ipc_log_violation(req: ipc::Req) -> Option<()> {
    ensure_ipc_and(|opt| {
        if let Some(client) = opt.as_mut() {
            let _ = client.send(&req);
        }
    })
}

pub(crate) fn ipc_log(level: ipc::LogLevel, msg: String) {
    let pid = unsafe { GetCurrentProcessId() };
    let _ = ensure_ipc_and(|opt| {
        if let Some(client) = opt.as_mut() {
            let _ = client.send(&ipc::Req::Log { pid, level, msg });
        }
    });
}

/// Get the current process executable path (lowercased).
fn get_own_exe_path() -> String {
    let mut buf = [0u16; 512];
    // SAFETY: buf is valid, len matches. GetModuleFileNameW writes a null-terminated string.
    let len = unsafe { winapi::um::libloaderapi::GetModuleFileNameW(
        std::ptr::null_mut(),
        buf.as_mut_ptr(),
        buf.len() as u32,
    )};
    if len == 0 {
        return String::new();
    }
    let s = String::from_utf16_lossy(&buf[..len as usize]);
    s.to_ascii_lowercase()
}

/// Extract the executable path from RTL_USER_PROCESS_PARAMETERS.
/// Returns empty string if extraction fails.
unsafe fn extract_child_exe(params: *mut c_void) -> String {
    if params.is_null() {
        return String::new();
    }
    // RTL_USER_PROCESS_PARAMETERS layout on x64 Windows 10/11:
    //   0x00: MaximumLength (ULONG), Length (ULONG)
    //   0x08: Flags (ULONG), DebugFlags (ULONG)
    //   0x10: ConsoleHandle (HANDLE), ConsoleFlags (ULONG) + pad
    //   0x20: StandardInput (HANDLE)
    //   0x28: StandardOutput (HANDLE)
    //   0x30: StandardError (HANDLE)
    //   0x38: CurrentDirectory (CURDIR — 0x18 bytes)
    //   0x50: DllPath (UNICODE_STRING — 0x10 bytes)
    //   0x60: ImagePathName (UNICODE_STRING — 0x10 bytes)
    //   0x70: CommandLine (UNICODE_STRING)
    //
    // Reading ImagePathName at offset 0x60 (NT path to child executable).
    let params_ptr = params as *const u8;
    let image_path_offset = 0x60usize;
    let ustr_ptr = params_ptr.add(image_path_offset) as *const UNICODE_STRING;
    if ustr_ptr.is_null() {
        return String::new();
    }
    let ustr = &*ustr_ptr;
    let char_count = (ustr.Length / 2) as usize;
    if char_count == 0 || ustr.Buffer.is_null() {
        return String::new();
    }
    let name_slice = std::slice::from_raw_parts(ustr.Buffer, char_count);
    policy::path::nt_to_dos_lower(name_slice).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// IO_STATUS_BLOCK helper
// ---------------------------------------------------------------------------

/// Write the Status field (at offset 0) of an IO_STATUS_BLOCK.
///
/// # SAFETY
/// IO_STATUS_BLOCK.Status/Pointer union begins at offset 0 on all Windows
/// x64 ABIs. Writing an i32 (NTSTATUS) to offset 0 is always correct.
// TODO: writes only 4 bytes into the 8-byte union slot on x64; upper
// 4 bytes retain previous garbage. Safe for callers reading Status
// (NTSTATUS = i32), unsafe for callers interpreting union as Pointer.
// Should zero the full ULONG_PTR before writing Status.
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
        return policy::path::nt_to_dos_lower(&full);
    }

    policy::path::nt_to_dos_lower(name_slice)
}

unsafe fn extract_raw_nt_path(attrs: *const OBJECT_ATTRIBUTES) -> Option<String> {
    if attrs.is_null() { return None; }
    let obj = &*attrs;
    if obj.ObjectName.is_null() { return None; }
    let ustr = &*obj.ObjectName;
    let char_count = (ustr.Length / 2) as usize;
    if char_count == 0 { return None; }
    let name_slice = std::slice::from_raw_parts(ustr.Buffer, char_count);
    Some(String::from_utf16_lossy(name_slice))
}

/// Returns Some(STATUS_ACCESS_DENIED) if the raw NT path in `attrs` is a
/// hard-blocked device (shadowcopy, physicaldrive, raw harddisk, dangerous
/// pipe). None otherwise → caller should call the original Nt* function.
///
/// SAFETY: `attrs` must be valid per NT calling convention.
unsafe fn check_device_block(attrs: *const OBJECT_ATTRIBUTES) -> Option<NTSTATUS> {
    let dev_path = extract_raw_nt_path(attrs)?;
    let utf16: Vec<u16> = dev_path.encode_utf16().collect();
    let device = policy::dev::nt_to_device_path(&utf16)?;
    let kind = policy::dev::classify_device(&device);
    if matches!(kind, policy::dev::DeviceKind::Unknown) {
        if is_trace() {
            ipc_log(
                ipc::LogLevel::Trace,
                format!("DENY device: {dev_path} kind={kind:?}"),
            );
        }
        Some(STATUS_ACCESS_DENIED)
    } else {
        None
    }
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
        // Not a DOS path — check if it's a device path that should be blocked.
        if let Some(status) = check_device_block(object_attributes as *const _) {
            set_io_status(io_status_block, status);
            return status;
        }
        return call_original!();
    };

    let write = is_write_access(desired_access, create_disposition);
    let decision = decide(&dos, write);

    match decision.mode {
        Mode::Passthrough => call_original!(),
        Mode::Deny => {
            if is_trace() {
                ipc_log(ipc::LogLevel::Trace, format!("DENY NtCreateFile: {dos} write={write}"));
            }
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
        if let Some(status) = check_device_block(object_attributes as *const _) {
            set_io_status(io_status_block, status);
            return status;
        }
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
        let parent_pid = unsafe { GetCurrentProcessId() };
        ipc_register_child(child_pid);
        // Send SpawnedChild with child exe path extracted from process parameters.
        let child_exe = extract_child_exe(process_parameters);
        // Track this PID as our spawned child so memory_guard/reg_hooks can
        // distinguish legitimate injection-target operations from external attacks.
        crate::process_tracker::mark_spawned(child_pid, parent_pid, child_exe.clone());
        ipc_spawned_child(parent_pid, child_pid, child_exe);
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

pub(crate) unsafe fn ntdll_export(name: &[u8]) -> Option<*const ()> {
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
    if std::env::var("FS_SANDBOX_TRACE").is_ok() {
        TRACE_ENABLED.store(true, std::sync::atomic::Ordering::Relaxed);
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

    let guard = std::env::var("FS_SANDBOX_GUARD").unwrap_or_else(|_| "full".into());
    let disabled = std::env::var("FS_SANDBOX_DISABLE_HOOKS").unwrap_or_default();
    let disabled_cats: Vec<String> = disabled.split(',').map(|s| s.trim().to_ascii_lowercase()).collect();
    let skip = |cat: &str| disabled_cats.iter().any(|d| d == cat);

    if !skip("fs") {
        install!(HOOK_NT_CREATE_FILE,              "NtCreateFile\0",              hook_nt_create_file,              FnNtCreateFile);
        install!(HOOK_NT_OPEN_FILE,                "NtOpenFile\0",                hook_nt_open_file,                FnNtOpenFile);
        install!(HOOK_NT_QUERY_ATTRIBUTES_FILE,    "NtQueryAttributesFile\0",     hook_nt_query_attributes_file,    FnNtQueryAttributesFile);
        install!(HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE, "NtQueryFullAttributesFile\0", hook_nt_query_full_attributes_file, FnNtQueryFullAttributesFile);
        install!(HOOK_NT_CREATE_USER_PROCESS,      "NtCreateUserProcess\0",       hook_nt_create_user_process,      FnNtCreateUserProcess);
    }

    if guard != "none" {
        // Hold anti_rec during guard installation so detour's internal
        // VirtualProtect calls (to patch ntdll stubs) pass through the
        // NtProtectVirtualMemory hook without triggering content scans
        // on ntdll's legitimate syscall instructions.
        let _install_guard = anti_rec::enter();
        if !skip("memory") {
            crate::memory_guard::install(&guard)?;
        }
        if !skip("inject") {
            crate::inject_guard::install()?;
        }
        if !skip("reg") {
            let _ = crate::reg_hooks::install();
        }
        if !skip("net") {
            let _ = crate::net_hooks::install();
        }
        if !skip("link") {
            let _ = crate::link_guard::install();
        }
        if !skip("alpc") {
            let _ = crate::alpc_guard::install();
        }
        if !skip("token") {
            let _ = crate::token_guard::install();
        }
        if !skip("ui") {
            let _ = crate::ui_guard::install();
        }

        if !skip("mitigations") {
            apply_mitigations(&guard);
        }
    }

    Ok(())
}

/// Apply kernel-enforced process mitigations from within the sandboxed process.
/// Called after all hooks are installed so our detour patching is already done.
fn apply_mitigations(guard: &str) {
    if guard == "none" {
        return;
    }
    use winapi::um::processthreadsapi::SetProcessMitigationPolicy;
    use winapi::um::winnt::PROCESS_MITIGATION_POLICY;

    // ExtensionPointDisablePolicy (6): blocks AppInit_DLLs, SetWindowsHookEx, IFEO.
    // Applied only in full mode — some programs (cargo, compilers) may load DLLs
    // that rely on extension points during startup.
    if guard == "full" {
        let ext_disable_flags: u32 = 1;
        // SAFETY: ext_disable_flags is valid for PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY.
        unsafe {
            SetProcessMitigationPolicy(
                6i32 as PROCESS_MITIGATION_POLICY,
                &ext_disable_flags as *const u32 as *mut _,
                std::mem::size_of::<u32>(),
            );
        }
    }

    if guard == "full" {
        // DynamicCodePolicy (2): blocks RWX/JIT
        let dyn_code_flags: u32 = 1; // ProhibitDynamicCode = bit 0
        // SAFETY: same — 4-byte struct with Flags DWORD.
        unsafe {
            SetProcessMitigationPolicy(
                2i32 as PROCESS_MITIGATION_POLICY, // ProcessDynamicCodePolicy
                &dyn_code_flags as *const u32 as *mut _,
                std::mem::size_of::<u32>(),
            );
        }

        // SignaturePolicy (8): only Microsoft-signed DLLs (subsequent loads)
        let sig_flags: u32 = 1; // MicrosoftSignedOnly = bit 0
        // SAFETY: same — PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY (4 bytes).
        unsafe {
            SetProcessMitigationPolicy(
                8i32 as PROCESS_MITIGATION_POLICY, // ProcessSignaturePolicy
                &sig_flags as *const u32 as *mut _,
                std::mem::size_of::<u32>(),
            );
        }
    }
}

/// Disable all detours. Called from DllMain(DLL_PROCESS_DETACH).
///
/// # SAFETY
/// Must be called on DLL_PROCESS_DETACH only. Errors are ignored because
/// the process is tearing down.
pub unsafe fn uninstall_hooks() {
    crate::ui_guard::uninstall();
    crate::token_guard::uninstall();
    crate::alpc_guard::uninstall();
    crate::link_guard::uninstall();
    crate::net_hooks::uninstall();
    crate::reg_hooks::uninstall();
    crate::inject_guard::uninstall();
    crate::memory_guard::uninstall();
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
