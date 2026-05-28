// ─── DLL injection and pre-launch scan ───────────────────────────────────────

use anyhow::{Context, Result};
use std::{ffi::OsStr, os::windows::ffi::OsStrExt, path::Path};
use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::HANDLE,
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Memory::{
                VirtualAllocEx, VirtualFreeEx,
                MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
                VIRTUAL_FREE_TYPE,
            },
        },
    },
};

/// Inject hook.dll into `process` using APC on the suspended `thread`.
pub(crate) fn inject_dll(process: HANDLE, thread: HANDLE, dll_path: &str) -> Result<()> {
    let dll_wide: Vec<u16> = OsStr::new(dll_path)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let byte_len = dll_wide.len() * 2;

    // SAFETY: process is a valid HANDLE with PROCESS_ALL_ACCESS; byte_len > 0.
    let remote_buf = unsafe {
        VirtualAllocEx(process, None, byte_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    };
    anyhow::ensure!(!remote_buf.is_null(), "VirtualAllocEx failed");

    let mut written = 0usize;
    // SAFETY: remote_buf just allocated in target; dll_wide valid for byte_len bytes.
    let write_ok = unsafe {
        WriteProcessMemory(process, remote_buf, dll_wide.as_ptr() as *const _, byte_len, Some(&mut written))
    };
    if write_ok.is_err() || written != byte_len {
        unsafe { VirtualFreeEx(process, remote_buf, 0, VIRTUAL_FREE_TYPE(0x8000)).ok() };
        anyhow::bail!("WriteProcessMemory failed");
    }

    let k32_wide: Vec<u16> = OsStr::new("kernel32.dll").encode_wide().chain(Some(0)).collect();
    // SAFETY: k32_wide is a valid null-terminated UTF-16 module name.
    let k32 = unsafe { GetModuleHandleW(PCWSTR(k32_wide.as_ptr()))? };
    // SAFETY: k32 is valid HMODULE; "LoadLibraryW\0" is valid PCSTR.
    let load_lib = unsafe { GetProcAddress(k32, windows::core::s!("LoadLibraryW")) }
        .context("GetProcAddress(LoadLibraryW) returned NULL")?;

    // Queue APC on the suspended main thread instead of CreateRemoteThread.
    // APC runs in the context of the main thread BEFORE the entry point,
    // avoiding CRT double-initialization that breaks cmd.exe.
    type FnNtQueueApcThread = unsafe extern "system" fn(
        HANDLE, *const core::ffi::c_void, *mut core::ffi::c_void,
        *mut core::ffi::c_void, *mut core::ffi::c_void,
    ) -> i32;
    let ntdll_w: Vec<u16> = OsStr::new("ntdll.dll").encode_wide().chain(Some(0)).collect();
    // SAFETY: ntdll is always loaded.
    let ntdll = unsafe { GetModuleHandleW(PCWSTR(ntdll_w.as_ptr()))? };
    let nt_queue = unsafe { GetProcAddress(ntdll, windows::core::s!("NtQueueApcThread")) }
        .context("NtQueueApcThread not found")?;
    // SAFETY: load_lib is LoadLibraryW address; remote_buf is the DLL path.
    let status = unsafe {
        let queue_fn: FnNtQueueApcThread = std::mem::transmute(nt_queue);
        queue_fn(
            thread,
            load_lib as *const _,
            remote_buf,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if status < 0 {
        unsafe { VirtualFreeEx(process, remote_buf, 0, VIRTUAL_FREE_TYPE(0x8000)).ok() };
        anyhow::bail!("NtQueueApcThread failed: 0x{status:08x}");
    }

    // APC will execute when thread resumes and enters alertable wait.
    // The main thread of a suspended CREATE_SUSPENDED process enters
    // alertable state during kernel32!BaseThreadInitThunk before calling
    // the entry point — our APC fires there.
    //
    // Note: we can't verify exit_code like with CreateRemoteThread.
    // If hook.dll fails to load, the process runs un-sandboxed.
    // inject_via_apc in hook.rs handles this for child processes
    // with a post-resume check.

    Ok(())
}

// ─── Pre-launch code integrity scan ──────────────────────────────────────────

/// Scan the main exe's .text section for direct syscall instructions before
/// resuming the child process. Returns Err if syscall instructions are found.
pub(crate) fn pre_launch_scan(
    process: HANDLE,
    target_exe: &str,
    target_pid: u32,
    violations_log: &Path,
) -> Result<()> {
    let image_base = get_image_base(process).context("get image base")?;
    if image_base == 0 {
        anyhow::bail!("image base is null");
    }

    // Read PE headers (4 KiB is enough for DOS + NT + section table)
    let mut pe_headers = vec![0u8; 4096];
    read_remote_memory(process, image_base, &mut pe_headers)
        .context("read PE headers")?;
    let text = policy::scan::pe_text_section(&pe_headers)
        .context("no .text section in PE")?;

    // Cap to a sane size to avoid pathological inputs
    let scan_size = (text.virtual_size as usize).min(64 * 1024 * 1024);
    let mut text_bytes = vec![0u8; scan_size];
    read_remote_memory(
        process,
        image_base + text.virtual_address as usize,
        &mut text_bytes,
    )
    .context("read .text section")?;

    let text_base = (image_base + text.virtual_address as usize) as u64;
    let hits = policy::scan::find_direct_syscalls(&text_bytes, text_base);
    if hits.is_empty() {
        return Ok(());
    }

    // Log violation
    log_pre_launch_violation(violations_log, target_pid, target_exe, &hits);
    eprintln!(
        "[VIOLATION] pre-launch scan: {} direct syscall(s) in {} (.text)",
        hits.len(),
        target_exe,
    );
    for h in hits.iter().take(5) {
        eprintln!("  - {} at offset 0x{:x}", h.kind, h.offset);
    }
    anyhow::bail!("direct syscall instructions found in target .text");
}

pub(crate) fn log_pre_launch_violation(
    log_path: &Path,
    target_pid: u32,
    target_exe: &str,
    hits: &[policy::scan::SyscallHit],
) {
    use std::io::Write;
    let hit_json: Vec<String> = hits
        .iter()
        .map(|h| format!("[\"0x{:x}\",\"{}\"]", h.offset, h.kind))
        .collect();
    let line = format!(
        "{{\"kind\":\"PreLaunchViolation\",\"target_pid\":{target_pid},\"target_exe\":\"{}\",\"hit_count\":{},\"hits\":[{}]}}\n",
        target_exe.replace('\\', "\\\\").replace('"', "\\\""),
        hits.len(),
        hit_json.join(","),
    );
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

/// Get the image base address of the main executable in the target process.
/// Reads PEB.ImageBaseAddress (offset 0x10 on x64).
pub(crate) fn get_image_base(process: HANDLE) -> Result<usize> {
    // NtQueryInformationProcess(ProcessBasicInformation = 0)
    // Returns PROCESS_BASIC_INFORMATION; PebBaseAddress is at offset 0x08.
    #[repr(C)]
    #[derive(Default)]
    struct ProcessBasicInformation {
        exit_status: i32,
        _pad0: u32,
        peb_base_address: usize,
        affinity_mask: usize,
        base_priority: i32,
        _pad1: u32,
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }

    // Resolve NtQueryInformationProcess from ntdll
    type FnNtQueryInformationProcess = unsafe extern "system" fn(
        HANDLE, u32, *mut core::ffi::c_void, u32, *mut u32,
    ) -> i32;

    let ntdll: Vec<u16> = OsStr::new("ntdll.dll").encode_wide().chain(Some(0)).collect();
    // SAFETY: ntdll is always loaded.
    let hmod = unsafe { GetModuleHandleW(PCWSTR(ntdll.as_ptr()))? };
    // SAFETY: hmod is valid; literal ASCII null-terminated name.
    let proc_addr = unsafe {
        GetProcAddress(hmod, windows::core::s!("NtQueryInformationProcess"))
    }
    .context("NtQueryInformationProcess not found")?;
    // SAFETY: proc_addr is the real NtQueryInformationProcess export.
    let nt_query: FnNtQueryInformationProcess =
        unsafe { std::mem::transmute(proc_addr) };

    let mut info = ProcessBasicInformation::default();
    let mut ret_len: u32 = 0;
    // SAFETY: info is valid for size_of writes; process is a valid handle.
    let status = unsafe {
        nt_query(
            process,
            0,
            &mut info as *mut _ as *mut _,
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut ret_len,
        )
    };
    if status < 0 {
        anyhow::bail!("NtQueryInformationProcess failed: 0x{status:x}");
    }
    if info.peb_base_address == 0 {
        anyhow::bail!("PEB base address is null");
    }

    // Read ImageBaseAddress at PEB + 0x10 (x64)
    let mut image_base_bytes = [0u8; 8];
    read_remote_memory(process, info.peb_base_address + 0x10, &mut image_base_bytes)
        .context("read PEB.ImageBaseAddress")?;
    Ok(usize::from_le_bytes(image_base_bytes))
}

pub(crate) fn read_remote_memory(process: HANDLE, addr: usize, buf: &mut [u8]) -> Result<()> {
    let mut read: usize = 0;
    // SAFETY: process is valid; buf is valid for buf.len() writes.
    let ok = unsafe {
        windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            process,
            addr as *const _,
            buf.as_mut_ptr() as *mut _,
            buf.len(),
            Some(&mut read),
        )
    };
    ok.context("ReadProcessMemory failed")?;
    if read != buf.len() {
        anyhow::bail!("short read: {read} of {}", buf.len());
    }
    Ok(())
}
