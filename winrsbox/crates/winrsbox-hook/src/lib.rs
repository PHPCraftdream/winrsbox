// hook.dll — injected into sandboxed processes.
// Entry point: DllMain.  All heavy work is in hooks.rs / inject.rs.
//
// Crate versions assumed:
//   detour2     = "0.9" (default-features = false, no nightly)
//   ntapi       = "0.4"
//   winapi      = "0.3"
//   widestring  = "1"
//   quick_cache = "0.6"
//   xxhash-rust = "0.8"

#![allow(non_snake_case)]

#[path = "core/anti_rec.rs"]
mod anti_rec;
#[path = "ipc/alpc_guard/mod.rs"]
pub mod alpc_guard;
#[path = "fs/fs_hooks/mod.rs"]
pub mod fs_hooks;
#[path = "core/hooked_attrs.rs"]
pub(crate) mod hooked_attrs;
#[path = "ipc/ipc_client/mod.rs"]
pub mod ipc_client;
// Effective install-time security config, resolved from the trusted session
// section ONLY (review XA 2026-09-20, S02). Declared beside ipc_client like
// every other ipc/ module.
#[path = "ipc/trusted_boot.rs"]
pub(crate) mod trusted_boot;
// Init-event handshake + SetProcessMitigationPolicy application (S10),
// moved out of hooks/mod.rs so it is unit-testable in one place.
#[path = "ipc/init_ack.rs"]
pub(crate) mod init_ack;
#[path = "ipc/com_guard/mod.rs"]
pub mod com_guard;
#[path = "core/cache.rs"]
pub mod cache;
#[path = "fs/dir_filter/mod.rs"]
pub mod dir_filter;
#[path = "fs/fs_metadata_guard/mod.rs"]
pub mod fs_metadata_guard;
#[path = "fs/path_info_guard.rs"]
pub mod path_info_guard;
#[path = "core/hooks/mod.rs"]
pub mod hooks;
#[path = "memory/inject.rs"]
mod inject;
#[path = "memory/inject_guard.rs"]
pub mod inject_guard;
#[path = "memory/memory_guard/mod.rs"]
pub mod memory_guard;
#[path = "system/net_hooks.rs"]
pub mod net_hooks;
#[path = "proc/proc_guard/mod.rs"]
pub mod proc_guard;
#[path = "proc/process_tracker.rs"]
pub mod process_tracker;
#[path = "proc/child_handles.rs"]
pub mod child_handles;
#[path = "core/scan_cache.rs"]
pub mod scan_cache;
#[path = "system/reg_hooks/mod.rs"]
pub mod reg_hooks;
// reg_overlay removed (M-A1): the launcher (policy::reg_overlay) is the
// single source of truth for sandboxed registry state. Hook routes all
// writes/deletes through IPC (Req::RegWrite / RegDeleteValue / RegDeleteKey).
#[path = "ipc/service_guard.rs"]
pub mod service_guard;
#[path = "ipc/shell_guard/mod.rs"]
pub mod shell_guard;
#[path = "system/system_guard.rs"]
pub mod system_guard;
#[path = "proc/token_guard.rs"]
pub mod token_guard;
#[path = "system/ui_guard.rs"]
pub mod ui_guard;

// Bench-only thin wrappers. Marked `#[doc(hidden)]` so they don't appear in
// the public API surface, but allow `cargo bench` to call `pub(crate)`
// internals from `hooks.rs`. Used by `benches/path_traversal.rs` (M-T4).
// Do not depend on these from non-bench code.
//
// `pub use hooks::{...}` cannot re-export `pub(crate)` items; thin wrappers
// inside the crate root can call them and expose the result as `pub`.
#[doc(hidden)]
pub mod bench_api {
    use ntapi::winapi::shared::ntdef::{NTSTATUS, OBJECT_ATTRIBUTES};

    /// Thin wrapper around `hooks::check_path_traversal` for bench access.
    ///
    /// # SAFETY
    /// Same contract as the wrapped function: `attrs` must be a valid
    /// `OBJECT_ATTRIBUTES` per the NT calling convention.
    pub unsafe fn check_path_traversal(
        attrs: *const OBJECT_ATTRIBUTES,
        create_options: u32,
    ) -> Option<NTSTATUS> {
        crate::hooks::check_path_traversal(attrs, create_options)
    }

    /// Thin wrapper around `hooks::needs_short_name_resolve` for bench access.
    pub fn needs_short_name_resolve(path: &str) -> bool {
        crate::hooks::needs_short_name_resolve(path)
    }
}

#[cfg(not(test))]
use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE, FALSE};
#[cfg(not(test))]
use winapi::um::libloaderapi::DisableThreadLibraryCalls;

#[cfg(not(test))]
const DLL_PROCESS_ATTACH: DWORD = 1;
#[cfg(not(test))]
const DLL_PROCESS_DETACH: DWORD = 0;

#[cfg(not(test))]
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    hinst: HINSTANCE,
    reason: DWORD,
    _reserved: LPVOID,
) -> BOOL {
    match reason {
        DLL_PROCESS_ATTACH => {
            DisableThreadLibraryCalls(hinst);
            match hooks::install_hooks() {
                Ok(()) => TRUE,
                Err(_) => {
                    crate::init_ack::signal_init_failure();
                    FALSE
                }
            }
        }
        DLL_PROCESS_DETACH => {
            hooks::uninstall_hooks();
            TRUE
        }
        _ => TRUE,
    }
}
