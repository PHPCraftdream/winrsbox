// hook.dll — injected into sandboxed processes.
// Entry point: DllMain.  All heavy work is in hooks.rs / inject.rs.
//
// Crate versions assumed:
//   detour      = "0.8" (default-features = false, no nightly)
//   ntapi       = "0.4"
//   winapi      = "0.3"
//   widestring  = "1"
//   quick_cache = "0.6"
//   xxhash-rust = "0.8"

#![allow(non_snake_case)]

mod anti_rec;
pub mod alpc_guard;
pub mod com_guard;
pub mod cache;
pub mod hooks;
mod inject;
pub mod inject_guard;
pub mod memory_guard;
pub mod net_hooks;
pub mod proc_guard;
pub mod process_tracker;
pub mod scan_cache;
pub mod reg_hooks;
pub mod reg_overlay;
pub mod service_guard;
pub mod token_guard;
pub mod ui_guard;

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
