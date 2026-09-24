// ─── DLL injection and pre-launch scan ───────────────────────────────────────

use anyhow::{Context, Result};
use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::Read,
    os::windows::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
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

/// Bound per-read chunk for the remote image scan: it bounds MEMORY, not
/// coverage — every byte of the requested range is read and decoded exactly
/// once (plus the 15-byte instruction overlap below), regardless of section
/// size. S06 gap 4 (XA review 2026-09-20): replaces the silent
/// `min(64 MiB)` truncation whose tail of a large section went unscanned.
/// Residual: a hostile image with an enormous claimed section size can cost
/// scan TIME (the read fails closed at the first unmapped page), never
/// unbounded scan memory.
const REMOTE_SCAN_CHUNK_BYTES: usize = 16 * 1024 * 1024;

/// Longest possible x86-64 instruction — chunk overlap so an instruction
/// straddling a chunk boundary is still decoded by the earlier pass.
const REMOTE_SCAN_CHUNK_OVERLAP: usize = 15;

/// Read+decode `[base, base + size)` out of the target image in bounded
/// chunks. Any read failure propagates — fail closed: the target must not
/// run over an image we could not fully check.
async fn scan_remote_region(
    process_raw: usize,
    base: usize,
    size: usize,
) -> Result<Vec<policy::scan::SyscallHit>> {
    let mut hits = Vec::new();
    let mut offset = 0usize;
    let workers = std::thread::available_parallelism()
        .map(|count| count.get().min(4))
        .unwrap_or(1);
    while offset < size {
        let mut tasks = Vec::with_capacity(workers);
        for _ in 0..workers {
            if offset >= size {
                break;
            }
            let start = offset;
            let body = (size - offset).min(REMOTE_SCAN_CHUNK_BYTES);
            let len = body.saturating_add(REMOTE_SCAN_CHUNK_OVERLAP).min(size - offset);
            offset += body;
            tasks.push(tokio::task::spawn_blocking(move || -> Result<_> {
                let address = base.checked_add(start).context("scan address overflow")?;
                let mut bytes = vec![0u8; len];
                read_remote_memory(HANDLE(process_raw as *mut _), address, &mut bytes)?;
                Ok(policy::scan::find_direct_syscalls_multi_entry(&bytes, address as u64)
                    .into_iter()
                    .map(|hit| policy::scan::SyscallHit {
                        offset: start + hit.offset,
                        kind: hit.kind,
                    })
                    .collect::<Vec<_>>())
            }));
        }
        let mut first_error = None;
        for task in tasks {
            match task.await {
                Ok(Ok(mut chunk_hits)) => hits.append(&mut chunk_hits),
                Ok(Err(error)) => {
                    first_error.get_or_insert(error);
                }
                Err(error) => {
                    first_error.get_or_insert(anyhow::Error::new(error));
                }
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
    }
    hits.sort_by_key(|hit| hit.offset);
    hits.dedup_by_key(|hit| hit.offset);
    Ok(hits)
}

/// Scan the main exe's executable sections for direct syscall instructions
/// before resuming the child process. Returns Err if syscall instructions are found.
pub(crate) async fn pre_launch_scan(
    process_raw: usize,
    target_exe: &str,
    target_pid: u32,
    violations_log: &Path,
) -> Result<()> {
    let cache_dir = std::env::current_exe().ok()
        .and_then(|exe| exe.parent().map(policy::pe_cache::cache_dir));
    let image_path = crate::pipe_server::query_process_image_path(target_pid);
    let cache_key = if let Some(path) = image_path {
        tokio::task::spawn_blocking(move || policy::pe_cache::file_key(Path::new(&path)))
            .await.ok().and_then(Result::ok)
    } else {
        None
    };
    if let (Some(dir), Some(key)) = (&cache_dir, &cache_key) {
        if policy::pe_cache::contains_clean(dir, key) {
            return Ok(());
        }
    }
    let image_base = get_image_base(HANDLE(process_raw as *mut _)).context("get image base")?;
    if image_base == 0 {
        anyhow::bail!("image base is null");
    }

    // Read PE headers (4 KiB is enough for DOS + NT + section table)
    let mut pe_headers = vec![0u8; 4096];
    read_remote_memory(HANDLE(process_raw as *mut _), image_base, &mut pe_headers)
        .context("read PE headers")?;
    // S06 gap 3 (XA review 2026-09-20): scan EVERY executable section, not
    // just ".text" — a target can carry additional IMAGE_SCN_MEM_EXECUTE
    // sections. S06 gap 4: no size cap — the old `min(64 MiB)` silently
    // left the tail of large sections unchecked; sections are read+decoded
    // in bounded chunks instead (see `scan_remote_region`).
    let exec_sections = policy::scan::pe_executable_sections(&pe_headers);
    if exec_sections.is_empty() {
        anyhow::bail!("no executable section in PE");
    }

    for section in &exec_sections {
        let sec_base = image_base + section.virtual_address as usize;
        let hits = scan_remote_region(process_raw, sec_base, section.virtual_size as usize).await?;
        if hits.is_empty() {
            continue;
        }

        // Log violation
        log_pre_launch_violation(violations_log, target_pid, target_exe, &hits);
        eprintln!(
            "[VIOLATION] pre-launch scan: {} direct syscall(s) in {} (executable section at RVA 0x{:x})",
            hits.len(),
            target_exe,
            section.virtual_address,
        );
        for h in hits.iter().take(5) {
            eprintln!("  - {} at offset 0x{:x}", h.kind, h.offset);
        }
        anyhow::bail!("direct syscall instructions found in target executable section");
    }
    if let (Some(dir), Some(key)) = (cache_dir, cache_key) {
        let _ = tokio::task::spawn_blocking(move || policy::pe_cache::record_clean(&dir, &key)).await;
    }
    Ok(())
}

pub(crate) fn log_pre_launch_violation(
    log_path: &Path,
    target_pid: u32,
    target_exe: &str,
    hits: &[policy::scan::SyscallHit],
) {
    // serde_json escapes control characters, so a hostile target path
    // cannot forge extra records in violations.log (same fix as the
    // pipe-side violation writers; audit 2026-09-19).
    let record = serde_json::json!({
        "kind": "PreLaunchViolation",
        "target_pid": target_pid,
        "target_exe": target_exe,
        "hit_count": hits.len(),
        "hits": hits
            .iter()
            .map(|h| serde_json::json!([format!("0x{:x}", h.offset), h.kind.to_string()]))
            .collect::<Vec<_>>(),
    });
    crate::pipe_server::append_violation_record(log_path, record);
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

// ─── Locate and verify hook.dll before injection ───────────────────────────
// Moved here from sandbox/mod.rs (layout-guard: that file was over the
// 1000-line limit) — "find hook.dll and verify its staged integrity before
// injecting it" belongs with the rest of this file's DLL-injection concerns.

pub(crate) fn find_hook_dll() -> Result<String> {
    let exe = std::env::current_exe()?;
    let dll = exe
        .parent()
        .unwrap_or(Path::new("."))
        .join("hook.dll");
    anyhow::ensure!(
        dll.exists(),
        "hook.dll not found at {}",
        dll.display()
    );
    let dll = dll.to_string_lossy().into_owned();
    // Defense-in-depth before injection: refuse self-installs inside the
    // guest's project tree (no policy rule can protect them there), then
    // verify the staged exe/DLL digests against the installer's integrity
    // manifest so a trojanized artifact becomes a loud refusal instead of a
    // silent injection of attacker-controlled code.
    verify_not_inside_guest_project_node_modules(&dll)?;
    verify_staged_artifacts(&dll)?;
    Ok(dll)
}

/// SHA-256 of a file via CNG's one-shot `BCryptHash` (no streaming state to
/// manage). Used by the staged-artifact integrity check below.
pub(super) fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    use windows::Win32::Security::Cryptography::{
        BCryptCloseAlgorithmProvider, BCryptHash, BCryptOpenAlgorithmProvider,
        BCRYPT_ALG_HANDLE, BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, BCRYPT_SHA256_ALGORITHM,
    };

    let mut alg = BCRYPT_ALG_HANDLE::default();
    // SAFETY: alg is a valid out handle pointer; BCRYPT_SHA256_ALGORITHM is a
    //         static null-terminated wide string; no implementation pin needed.
    let status = unsafe {
        BCryptOpenAlgorithmProvider(
            &mut alg,
            BCRYPT_SHA256_ALGORITHM,
            PCWSTR::null(),
            BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
        )
    };
    if status.0 < 0 {
        anyhow::bail!("BCryptOpenAlgorithmProvider failed: 0x{:08X}", status.0);
    }
    let data = std::fs::read(path)
        .with_context(|| format!("read {} for hashing", path.display()))?;
    let mut out = [0u8; 32];
    // SAFETY: alg was opened above; out is a valid 32-byte buffer (the
    //         SHA-256 digest size).
    let status = unsafe { BCryptHash(alg, None, &data, &mut out) };
    // SAFETY: alg was opened above and is not used after this point.
    unsafe { let _ = BCryptCloseAlgorithmProvider(alg, 0); }
    if status.0 < 0 {
        anyhow::bail!("BCryptHash failed: 0x{:08X}", status.0);
    }
    Ok(out)
}

/// Lowercase-hex encoding of a 32-byte digest (the manifest's format).
pub(super) fn digest_to_hex(d: &[u8; 32]) -> String {
    d.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Verify the launcher exe and the hook.dll it is about to inject still match
/// the digests recorded in `integrity.json` next to the exe (written by the
/// npm installer at deploy time). A MISSING manifest is fine — that is an
/// unmanaged deployment (e.g. a dev `cargo build`) with nothing to verify.
/// A present-but-mismatched manifest fails closed: a silently swapped
/// exe/DLL turns into a loud refusal instead of an injection of
/// attacker-controlled code.
pub(super) fn verify_staged_artifacts_in(exe_path: &Path, dll_path: &Path) -> Result<()> {
    let manifest_path = exe_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("integrity.json");
    if !manifest_path.exists() {
        return Ok(());
    }
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&manifest_path)
            .with_context(|| format!("read integrity manifest {}", manifest_path.display()))?,
    )
    .with_context(|| format!("parse integrity manifest {}", manifest_path.display()))?;

    anyhow::ensure!(
        manifest.get("algorithm").and_then(|v| v.as_str()) == Some("sha256"),
        "integrity manifest {} must declare algorithm == \"sha256\"",
        manifest_path.display()
    );
    let files = manifest
        .get("files")
        .and_then(|v| v.as_object())
        .with_context(|| format!("integrity manifest {} has no `files` object", manifest_path.display()))?;
    let expected = |name: &str| -> Result<String> {
        let v = files
            .get(name)
            .and_then(|v| v.as_str())
            .with_context(|| format!("integrity manifest files[\"{name}\"] missing or not a string"))?;
        // Fail closed on anything that is not a 64-char lowercase-hex digest —
        // a manifest we cannot strictly parse is a manifest we cannot trust.
        anyhow::ensure!(
            v.len() == 64 && v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "integrity manifest files[\"{name}\"] is not a 64-char lowercase-hex SHA-256 digest"
        );
        Ok(v.to_ascii_lowercase())
    };
    let want_exe = expected("winrsbox.exe")?;
    let want_dll = expected("hook.dll")?;

    let actual_exe = digest_to_hex(&sha256_file(exe_path)?);
    anyhow::ensure!(
        actual_exe == want_exe,
        "integrity check FAILED for {}: expected sha256 {}…, actual {}… — \
         the launcher binary was modified after install; refusing to run",
        exe_path.display(),
        &want_exe[..16],
        &actual_exe[..16]
    );
    let actual_dll = digest_to_hex(&sha256_file(dll_path)?);
    anyhow::ensure!(
        actual_dll == want_dll,
        "integrity check FAILED for {}: expected sha256 {}…, actual {}… — \
         hook.dll was modified after install; refusing to inject it",
        dll_path.display(),
        &want_dll[..16],
        &actual_dll[..16]
    );
    Ok(())
}

/// `verify_staged_artifacts_in` bound to the real launcher exe.
fn verify_staged_artifacts(dll_path: &str) -> Result<()> {
    let exe = std::env::current_exe()?;
    verify_staged_artifacts_in(&exe, Path::new(dll_path))
}

/// Refuse to run when the launcher itself is installed inside the sandboxed
/// project's `node_modules`. There the project_root passthrough short-circuits
/// every policy rule (policy/src/decide.rs compute()), so a guest could
/// trojanize winrsbox.exe/hook.dll for the NEXT run — no deny rule can fix
/// that. The only remedy is refusing to launch from such a location.
fn verify_not_inside_guest_project_node_modules(dll_path: &str) -> Result<()> {
    // Canonical form for comparison: backslash separators, lowercased,
    // `\\?\` device prefix stripped (current_exe can return it).
    let normalize = |p: &Path| -> String {
        // S11: kernel-identity fold — ASCII folds byte-identically to the old
        // ASCII-only lowercase, non-ASCII compares by NTFS identity too.
        let lossy = p.to_string_lossy();
        let folded = policy::path::nt_case_fold(&lossy);
        let s = folded.replace('/', "\\");
        s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
    };
    let exe = std::env::current_exe()?;
    let exe_dir = match exe.parent() {
        Some(d) => normalize(d),
        // No parent dir → cannot be inside anything.
        None => return Ok(()),
    };
    let nm_root = normalize(&std::env::current_dir()?.join("node_modules"));
    // Containment mirrors policy/src/decide.rs path_contained_in: prefix
    // match + separator boundary, so `...\node_modules` does not match a
    // sibling like `...\node_modules_bak`.
    let contained = exe_dir.starts_with(&nm_root)
        && (exe_dir.len() == nm_root.len()
            || exe_dir.as_bytes().get(nm_root.len()) == Some(&b'\\'));
    anyhow::ensure!(
        !contained,
        "refusing to launch: the winrsbox install itself ({}, containing {}) sits inside \
         the sandboxed project's node_modules, where the guest's project_root passthrough \
         makes every policy rule moot — a sandboxed process could trojanize winrsbox.exe \
         for the next run. Run the sandbox from a different directory or install winrsbox \
         globally.",
        exe_dir,
        dll_path
    );
    Ok(())
}

/// Pre-S07 C: overlay root, keyed by basename only:
/// `<local_appdata>/.winrsbox/<basename>/workdir`.
pub(crate) fn legacy_c_overlay_root(local_appdata: &Path, project_root: &Path) -> PathBuf {
    let name = project_root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "session".to_string());
    local_appdata.join(".winrsbox").join(name).join("workdir")
}

/// `FILE_ATTRIBUTE_REPARSE_POINT` (winnt.h). Set on any reparse point —
/// symlink, junction, mount point, and others.
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

fn is_plain_dir(md: &std::fs::Metadata) -> bool {
    md.is_dir() && md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
}

/// Create/reuse the current C: overlay root and return it with the pre-S07
/// path. Migration waits until the policy database identifies owned entries.
pub(crate) fn prepare_c_overlay_root(
    local_appdata: &Path,
    project_root: &Path,
) -> Result<(PathBuf, PathBuf)> {
    let c_root = super::ensure_c_overlay_root(local_appdata, project_root)?;
    let legacy = legacy_c_overlay_root(local_appdata, project_root);
    Ok((c_root, legacy))
}

pub(crate) fn complete_c_overlay_migration(
    policy: &policy::Policy,
    local_appdata: &Path,
    legacy: &Path,
    c_root: &Path,
) -> Result<()> {
    if policy.legacy_c_overlay_migration_complete(c_root)? {
        let leftovers = policy.overlay_values_under_root(legacy)?;
        anyhow::ensure!(
            leftovers.is_empty(),
            "legacy C: overlay migration is marked complete, but OVERLAY_IDX still references {}; refusing to launch",
            leftovers[0].display()
        );
        return Ok(());
    }

    let indexed_paths = policy.overlay_values_under_root(legacy)?;
    let (copied, unattributed_legacy) =
        migrate_legacy_c_overlay(local_appdata, legacy, c_root, &indexed_paths)?;
    if unattributed_legacy {
        eprintln!(
            "[sandbox] legacy C: overlay {} contains entries but this policy DB has no indexed C: overlays; leaving shared data untouched",
            legacy.display()
        );
    }
    if copied > 0 {
        eprintln!(
            "[sandbox] copied {copied} indexed legacy C: overlay entries into {}",
            c_root.display()
        );
    }
    let rebased = policy.rebase_legacy_c_overlay_and_mark_complete(legacy, c_root)?;
    if rebased > 0 {
        eprintln!(
            "[sandbox] rebased {rebased} legacy C: overlay index entries to {}",
            c_root.display()
        );
    }
    Ok(())
}

/// Copy indexed entries from the pre-S07 C: root. Source files remain intact;
/// any failure aborts before rebase. The bool reports unattributed legacy
/// entries when this policy has no indexed paths.
pub(crate) fn migrate_legacy_c_overlay(
    local_appdata: &Path,
    legacy: &Path,
    new_root: &Path,
    indexed_paths: &[PathBuf],
) -> Result<(usize, bool)> {
    let rel = legacy
        .strip_prefix(local_appdata)
        .context("legacy C: overlay root is outside LOCALAPPDATA")?;
    let mut cur = local_appdata.to_path_buf();
    for comp in rel.components() {
        cur.push(comp);
        match std::fs::symlink_metadata(&cur) {
            Ok(md) if is_plain_dir(&md) => {}
            Ok(_) => anyhow::bail!(
                "legacy C: overlay component {} is not a plain directory",
                cur.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, false)),
            Err(e) => return Err(e).with_context(|| format!("stat {}", cur.display())),
        }
    }
    if indexed_paths.is_empty() {
        let mut entries = fs::read_dir(legacy)
            .with_context(|| format!("read legacy overlay {}", legacy.display()))?;
        let has_unattributed_entries = match entries.next() {
            Some(Ok(_)) => true,
            Some(Err(e)) => return Err(e).with_context(|| format!("read legacy overlay {}", legacy.display())),
            None => false,
        };
        return Ok((0, has_unattributed_entries));
    }
    let indexed_relatives = indexed_paths
        .iter()
        .map(|indexed_path| {
            let relative = strip_path_prefix_ascii_case_insensitive(indexed_path, legacy)
                .with_context(|| {
                    format!(
                        "indexed overlay {} is outside legacy root",
                        indexed_path.display()
                    )
                })?;
            validate_relative_overlay_path(indexed_path, &relative)?;
            Ok(normalized_relative_key(&relative))
        })
        .collect::<Result<std::collections::HashSet<_>>>()?;
    validate_legacy_indexed_files(legacy, &indexed_relatives)?;

    let mut copied = 0;
    for indexed_path in indexed_paths {
        let relative = strip_path_prefix_ascii_case_insensitive(indexed_path, legacy)
            .with_context(|| {
                format!(
                    "indexed overlay {} is outside legacy root",
                    indexed_path.display()
                )
            })?;
        validate_relative_overlay_path(indexed_path, &relative)?;
        let source = legacy.join(&relative);
        let destination = new_root.join(&relative);
        ensure_plain_source_ancestors(legacy, relative.parent().unwrap_or_else(|| Path::new("")))?;
        match fs::symlink_metadata(&source) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("stat legacy overlay {}", source.display())),
            Ok(source_md) if !is_plain_entry(&source_md) => {
                anyhow::bail!(
                    "legacy overlay entry {} is a reparse point or unsupported file type",
                    source.display()
                );
            }
            Ok(source_md) if source_md.is_dir() => {
                ensure_plain_directory(new_root, &relative)?;
            }
            Ok(_) => {
                ensure_plain_directory(new_root, relative.parent().unwrap_or_else(|| Path::new("")))?;
                if copy_file_without_overwrite(&source, &destination)? {
                    copied += 1;
                }
            }
        }
    }
    Ok((copied, false))
}

fn validate_relative_overlay_path(indexed_path: &Path, relative: &Path) -> Result<()> {
    anyhow::ensure!(
        relative
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_))),
        "indexed overlay {} has an unsafe relative path",
        indexed_path.display()
    );
    Ok(())
}

fn normalized_relative_key(relative: &Path) -> String {
    let normalized = relative.to_string_lossy().replace('/', "\\");
    policy::path::nt_case_fold(&normalized).into_owned()
}

fn validate_legacy_indexed_files(
    root: &Path,
    indexed_relatives: &std::collections::HashSet<String>,
) -> Result<()> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).with_context(|| format!("read legacy overlay {}", dir.display()))? {
            let entry = entry.with_context(|| format!("read entry in legacy overlay {}", dir.display()))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .with_context(|| format!("stat legacy overlay entry {}", path.display()))?;
            anyhow::ensure!(
                is_plain_entry(&metadata),
                "legacy overlay entry {} is a reparse point or unsupported file type",
                path.display()
            );
            if metadata.is_dir() {
                pending.push(path);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .context("legacy overlay entry escaped its root")?;
                anyhow::ensure!(
                    indexed_relatives.contains(&normalized_relative_key(relative)),
                    "unindexed legacy C: overlay file {} has no OVERLAY_IDX entry; refusing to rebase",
                    path.display()
                );
            }
        }
    }
    Ok(())
}

fn strip_path_prefix_ascii_case_insensitive(path: &Path, root: &Path) -> Option<PathBuf> {
    let mut path_components = path.components();
    for root_component in root.components() {
        let path_component = path_components.next()?;
        if !path_component
            .as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&root_component.as_os_str().to_string_lossy())
        {
            return None;
        }
    }
    Some(path_components.fold(PathBuf::new(), |mut relative, component| {
        relative.push(component.as_os_str());
        relative
    }))
}

fn is_plain_entry(md: &std::fs::Metadata) -> bool {
    md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 && (md.is_dir() || md.is_file())
}

fn ensure_plain_directory(root: &Path, relative: &Path) -> Result<()> {
    let root_md = fs::symlink_metadata(root)
        .with_context(|| format!("stat overlay root {}", root.display()))?;
    anyhow::ensure!(
        is_plain_dir(&root_md),
        "overlay root {} is not a plain directory",
        root.display()
    );
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            anyhow::bail!("unsafe overlay directory component in {}", relative.display());
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(md) if is_plain_dir(&md) => {}
            Ok(_) => anyhow::bail!(
                "overlay destination component {} is not a plain directory",
                current.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).with_context(|| format!("create overlay directory {}", current.display()))?;
                let md = fs::symlink_metadata(&current)
                    .with_context(|| format!("verify overlay directory {}", current.display()))?;
                anyhow::ensure!(
                    is_plain_dir(&md),
                    "overlay destination component {} is not a plain directory",
                    current.display()
                );
            }
            Err(e) => return Err(e).with_context(|| format!("stat overlay directory {}", current.display())),
        }
    }
    Ok(())
}

fn ensure_plain_source_ancestors(root: &Path, relative: &Path) -> Result<()> {
    let root_md = fs::symlink_metadata(root)
        .with_context(|| format!("stat legacy overlay root {}", root.display()))?;
    anyhow::ensure!(
        is_plain_dir(&root_md),
        "legacy overlay root {} is not a plain directory",
        root.display()
    );
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            anyhow::bail!("unsafe legacy overlay directory component in {}", relative.display());
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(md) if is_plain_dir(&md) => {}
            Ok(_) => anyhow::bail!(
                "legacy overlay component {} is not a plain directory",
                current.display()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e).with_context(|| format!("stat legacy overlay directory {}", current.display())),
        }
    }
    Ok(())
}

fn copy_file_without_overwrite(source: &Path, destination: &Path) -> Result<bool> {
    if let Some(equal) = existing_destination_matches(source, destination)? {
        anyhow::ensure!(
            equal,
            "legacy overlay conflict at {}; refusing to overwrite",
            destination.display()
        );
        return Ok(false);
    }

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
    let parent = destination.parent().context("overlay destination has no parent")?;
    loop {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".winrsbox-migrate-{}-{id}.tmp", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&candidate) {
            Ok(mut output) => {
                let result = (|| -> Result<bool> {
                    let mut input = File::open(source)
                        .with_context(|| format!("open legacy overlay {}", source.display()))?;
                    std::io::copy(&mut input, &mut output)
                        .with_context(|| format!("copy legacy overlay {}", source.display()))?;
                    output.sync_all().context("flush migrated overlay file")?;
                    drop(output);
                    link_staged_file_no_replace(&candidate, destination, source)
                })();
                let _ = fs::remove_file(&candidate);
                return result;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("create migration temp file in {}", parent.display()))
            }
        }
    }
}

fn link_staged_file_no_replace(staged: &Path, destination: &Path, source: &Path) -> Result<bool> {
    match fs::hard_link(staged, destination) {
        Ok(()) => Ok(true),
        Err(e) => {
            if let Some(equal) = existing_destination_matches(source, destination)? {
                anyhow::ensure!(
                    equal,
                    "legacy overlay conflict at {}; refusing to overwrite",
                    destination.display()
                );
                return Ok(false);
            }
            Err(e).with_context(|| {
                format!(
                    "atomically install migrated overlay at {}; hard links are required",
                    destination.display()
                )
            })
        }
    }
}

fn existing_destination_matches(source: &Path, destination: &Path) -> Result<Option<bool>> {
    match fs::symlink_metadata(destination) {
        Ok(md) => {
            anyhow::ensure!(
                md.is_file() && md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
                "overlay destination {} is not a regular file",
                destination.display()
            );
            Ok(Some(files_equal(source, destination)?))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("stat overlay destination {}", destination.display())),
    }
}

fn files_equal(left: &Path, right: &Path) -> Result<bool> {
    let left_md = fs::metadata(left).with_context(|| format!("stat {}", left.display()))?;
    let right_md = fs::metadata(right).with_context(|| format!("stat {}", right.display()))?;
    if left_md.len() != right_md.len() {
        return Ok(false);
    }
    let mut left_file = File::open(left).with_context(|| format!("open {}", left.display()))?;
    let mut right_file = File::open(right).with_context(|| format!("open {}", right.display()))?;
    let mut left_buf = [0u8; 16 * 1024];
    let mut right_buf = [0u8; 16 * 1024];
    loop {
        let left_read = left_file.read(&mut left_buf)?;
        let right_read = right_file.read(&mut right_buf)?;
        if left_read != right_read || left_buf[..left_read] != right_buf[..right_read] {
            return Ok(false);
        }
        if left_read == 0 {
            return Ok(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_hardlink_failure_does_not_publish_destination() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let source = dir.path().join("legacy.bin");
        let staged = dir.path().join("staged.tmp");
        let destination = dir.path().join("missing-parent").join("overlay.bin");
        fs::write(&source, b"legacy contents").expect("write legacy source");
        fs::write(&staged, b"legacy contents").expect("write staged file");

        let err = link_staged_file_no_replace(&staged, &destination, &source)
            .expect_err("link to a missing parent must fail");
        assert!(err.to_string().contains("hard links are required"));
        assert!(!destination.exists(), "failure must not publish a partial destination");
        assert_eq!(fs::read(&staged).expect("read staged file"), b"legacy contents");
        assert_eq!(fs::read(&source).expect("read legacy source"), b"legacy contents");
    }

    /// The pre-launch record lands in the same violations.log audit trail
    /// as the pipe-side violation records; a hostile target path must not
    /// be able to forge extra records there (audit 2026-09-19).
    #[test]
    fn pre_launch_record_cannot_be_forged_by_hostile_target() {
        let dir = tempfile::tempdir().unwrap();
        let vlog = dir.path().join("violations.log");
        let hostile = "c:\\evil\" \n {\"pid\":666,\"kind\":\"PreLaunchViolation\"}\r\n\\";
        let hits = vec![
            policy::scan::SyscallHit {
                offset: 0x1400,
                kind: policy::scan::SyscallKind::Syscall,
            },
            policy::scan::SyscallHit {
                offset: 0x1600,
                kind: policy::scan::SyscallKind::Int2e,
            },
        ];
        log_pre_launch_violation(&vlog, 42, hostile, &hits);

        let raw = std::fs::read_to_string(&vlog).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 1, "one record must be one line: {raw}");
        let parsed: serde_json::Value = serde_json::from_str(lines[0])
            .expect("the record must be one complete JSON object");
        assert_eq!(parsed["target_pid"], 42);
        assert_eq!(
            parsed["target_exe"], hostile,
            "hostile path must round-trip exactly, not forge a record"
        );
        assert_eq!(parsed["hit_count"], 2);
        assert_eq!(parsed["hits"][0][0], "0x1400");
        assert_eq!(parsed["hits"][0][1], "syscall");
        assert_eq!(parsed["hits"][1][1], "int 2eh");
    }
}
