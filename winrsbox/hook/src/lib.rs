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

mod anti_rec;
pub mod alpc_guard;
pub mod fs_hooks;
pub(crate) mod hooked_attrs;
pub mod ipc_client;
pub mod com_guard;
pub mod cache;
pub mod dir_filter;
pub mod fs_metadata_guard;
pub mod path_info_guard;
pub mod hooks;
mod inject;
pub mod inject_guard;
pub mod memory_guard;
pub mod net_hooks;
pub mod proc_guard;
pub mod process_tracker;
pub mod scan_cache;
pub mod reg_hooks;
// reg_overlay removed (M-A1): the launcher (policy::reg_overlay) is the
// single source of truth for sandboxed registry state. Hook routes all
// writes/deletes through IPC (Req::RegWrite / RegDeleteValue / RegDeleteKey).
pub mod service_guard;
pub mod shell_guard;
pub mod system_guard;
pub mod token_guard;
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
            if hooks::install_hooks().is_ok() { TRUE } else { FALSE }
        }
        DLL_PROCESS_DETACH => {
            hooks::uninstall_hooks();
            TRUE
        }
        _ => TRUE,
    }
}
