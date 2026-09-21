use super::c_void;
use super::GetCurrentProcessId;
use super::HANDLE;
use super::policy::{MEM_COMMIT, READABLE_MASK, module_path_for_address, protect_name};

// Recorded (address, first-two-bytes) snapshot for every detour this module
// installs. A patched ntdll syscall stub starts with the detour jump
// (0xE9 rel32, or 0xFF 0x25 for the x64 absolute-jump form); the original
// stub starts with `4c 8b` (mov r10, rcx). Any mismatch against the
// post-install snapshot — including a page made unreadable — means the detour
// was overwritten. Only this module's own detours are recorded; the deny path
// above covers every other detour generically (they all live in the same
// critical-module executable pages).
pub(crate) static DETOUR_WATCH: std::sync::Mutex<Vec<(usize, [u8; 2])>> = std::sync::Mutex::new(Vec::new());
pub(crate) static MEMGUARD_UNINSTALLING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// True once `begin_teardown` has run, i.e. we are inside DLL_PROCESS_DETACH
/// and every remaining `GenericDetour::disable()` is OUR OWN restoration of
/// the original prologue bytes.
///
/// Teardown is indistinguishable from an unhook attempt by inspection alone —
/// both make a critical module's executable page writable and put the
/// original bytes back. The install window is discriminated by `anti_rec`
/// (hooks.rs holds it across every `enable()`); the teardown window has no
/// such carrier, because `uninstall_hooks` runs from the loader, not from
/// inside a hook. This flag is that carrier.
///
/// It does not widen what a guest can do. Reaching the teardown path at all
/// means reaching DLL_PROCESS_DETACH, and `uninstall_hooks` disables every
/// detour there regardless of this flag — a guest that can trigger the
/// teardown has already won, with or without the check below.
pub(crate) fn teardown_in_progress() -> bool {
    MEMGUARD_UNINSTALLING.load(std::sync::atomic::Ordering::Acquire)
}

/// True when a detour's current bytes no longer match its post-install
/// snapshot. An unreadable target counts as tampered (fail closed).
pub(crate) fn detour_bytes_tampered(expected: [u8; 2], current: Option<[u8; 2]>) -> bool {
    match current {
        Some(cur) => cur != expected,
        None => true,
    }
}

/// First watch entry whose current bytes differ from its snapshot, if any.
/// `read` is injectable for testing.
pub(crate) fn first_tampered_detour(
    watch: &[(usize, [u8; 2])],
    read: impl Fn(usize) -> Option<[u8; 2]>,
) -> Option<usize> {
    watch
        .iter()
        .find(|(addr, expected)| detour_bytes_tampered(*expected, read(*addr)))
        .map(|(addr, _)| *addr)
}

/// Read two code bytes at `addr` if the page is committed and readable;
/// None otherwise.
pub(crate) fn read_code_bytes(addr: usize) -> Option<[u8; 2]> {
    if addr == 0 {
        return None;
    }
    // SAFETY: VirtualQuery is safe on any address — returns 0 on failure.
    let mut mbi: winapi::um::winnt::MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        winapi::um::memoryapi::VirtualQuery(
            addr as *const c_void,
            &mut mbi,
            std::mem::size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
        )
    };
    if ret == 0 || mbi.State != MEM_COMMIT || mbi.Protect & READABLE_MASK == 0 {
        return None;
    }
    // SAFETY: VirtualQuery just reported addr as committed and readable; the
    // 2-byte read stays within the reported region.
    Some(unsafe { std::ptr::read(addr as *const [u8; 2]) })
}

/// Re-verify the recorded detour prologues and terminate on the first
/// mismatch. Called after an allowed operation that overlapped critical-module
/// executable pages. The reported target address is the tampered detour site.
pub(crate) fn verify_detours_or_die(kind: ipc::AllocKind, protect: u32, region_size: u64) {
    if teardown_in_progress() {
        return;
    }
    let tampered = {
        let watch = match DETOUR_WATCH.lock() {
            Ok(w) => w,
            Err(poisoned) => poisoned.into_inner(),
        };
        first_tampered_detour(&watch, read_code_bytes)
    };
    if let Some(addr) = tampered {
        report_and_terminate(kind, protect, region_size, addr as u64);
    }
}

/// Record a freshly installed detour for tamper verification. Called once per
/// target right after enable(), from the single-threaded install path.
pub(crate) fn record_detour_for_watch(addr: usize) {
    if addr == 0 {
        return;
    }
    if let Some(bytes) = read_code_bytes(addr) {
        if let Ok(mut watch) = DETOUR_WATCH.lock() {
            watch.push((addr, bytes));
        }
    }
}

// ---------------------------------------------------------------------------
// Stack capture
// ---------------------------------------------------------------------------

pub(crate) fn capture_stack(skip: u32, count: u32) -> Vec<u64> {
    let count = count.min(62); // RtlCaptureStackBackTrace max is 62
    let mut frames = vec![std::ptr::null_mut::<c_void>(); count as usize];
    // SAFETY: frames buffer is valid for `count` pointers.
    // RtlCaptureStackBackTrace is always available in ntdll.
    // SAFETY: frames buffer is valid for `count` pointers. RtlCaptureStackBackTrace
    // is in ntdll (re-exported via winapi::um::winnt) and is always available.
    let captured = unsafe {
        winapi::um::winnt::RtlCaptureStackBackTrace(
            skip,
            count,
            frames.as_mut_ptr(),
            std::ptr::null_mut(),
        )
    };
    frames.truncate(captured as usize);
    frames.iter().map(|p| *p as u64).collect()
}

// ---------------------------------------------------------------------------
// Self-process check
// ---------------------------------------------------------------------------

pub(crate) const NT_CURRENT_PROCESS: isize = -1;

pub(crate) fn is_current_process(handle: HANDLE) -> bool {
    if handle as isize == NT_CURRENT_PROCESS {
        return true;
    }
    if handle.is_null() {
        return false;
    }
    // Real handle: check if it points to our own PID
    // SAFETY: GetProcessId is safe on any HANDLE; returns 0 on invalid.
    unsafe {
        let pid = winapi::um::processthreadsapi::GetProcessId(handle);
        pid != 0 && pid == GetCurrentProcessId()
    }
}

// ---------------------------------------------------------------------------
// Report + terminate
// ---------------------------------------------------------------------------

pub(crate) fn report_and_terminate(kind: ipc::AllocKind, protect: u32, region_size: u64, target_addr: u64) -> ! {
    let pid = unsafe { GetCurrentProcessId() };

    // Capture stack (skip 3: report_and_terminate → hook_fn → relay)
    let stack = capture_stack(3, 16);

    // Find the first non-system frame for caller info
    let caller_pc = stack.first().copied().unwrap_or(0);
    let caller_module = module_path_for_address(caller_pc as *const c_void);

    let exe = get_own_exe_path();

    // IPC: fire-and-forget (best effort)
    let _ = crate::hooks::ipc_log_violation(ipc::Req::MemoryViolation {
        pid,
        exe: exe.clone(),
        kind,
        requested_protect: protect,
        region_size,
        target_address: target_addr,
        caller_pc,
        caller_module: caller_module.clone(),
        stack_top: stack.clone(),
    });

    // Local fallback log to %TEMP%
    write_local_fallback(pid, &exe, kind, protect, region_size, target_addr, caller_pc, &caller_module, &stack);

    // OutputDebugStringW for -d mode
    let msg = format!(
        "[VIOLATION] pid={pid} kind={kind} protect={} caller={} pc=0x{caller_pc:x}\0",
        protect_name(protect),
        caller_module.as_deref().unwrap_or("<anonymous>"),
    );
    let wide: Vec<u16> = msg.encode_utf16().collect();
    // SAFETY: wide is a valid null-terminated UTF-16 string.
    unsafe { winapi::um::debugapi::OutputDebugStringW(wide.as_ptr()) };

    // Terminate
    // SAFETY: GetCurrentProcess() always returns a valid pseudo-handle.
    unsafe {
        winapi::um::processthreadsapi::TerminateProcess(
            winapi::um::processthreadsapi::GetCurrentProcess(),
            0xC000_0005, // STATUS_ACCESS_VIOLATION
        );
    }
    // TerminateProcess is asynchronous on self; loop to prevent returning
    loop {
        unsafe { winapi::um::synchapi::Sleep(1000) };
    }
}

pub(crate) fn get_own_exe_path() -> String {
    let mut buf = [0u16; 512];
    // SAFETY: buf is valid, len matches.
    let len = unsafe {
        winapi::um::libloaderapi::GetModuleFileNameW(
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            buf.len() as u32,
        )
    };
    if len == 0 { String::new() } else { String::from_utf16_lossy(&buf[..len as usize]) }
}

fn write_local_fallback(
    pid: u32, exe: &str, kind: ipc::AllocKind, protect: u32,
    size: u64, addr: u64, caller_pc: u64, caller_module: &Option<String>,
    stack: &[u64],
) {
    let tmp = std::env::temp_dir();
    let path = tmp.join(format!("fs-sandbox-violation-{pid}.log"));
    let stack_str: Vec<String> = stack.iter().map(|f| format!("0x{f:x}")).collect();
    let line = format!(
        "{{\"pid\":{pid},\"exe\":\"{}\",\"kind\":\"{kind}\",\"protect\":\"{}\",\"size\":{size},\"addr\":\"0x{addr:x}\",\"caller_pc\":\"0x{caller_pc:x}\",\"caller_module\":{},\"stack\":[{}]}}\n",
        exe.replace('\\', "\\\\").replace('"', "\\\""),
        protect_name(protect),
        match caller_module {
            Some(m) => format!("\"{}\"", m.replace('\\', "\\\\").replace('"', "\\\"")),
            None => "null".to_string(),
        },
        stack_str.join(","),
    );
    let _ = std::fs::write(&path, line.as_bytes());
}

