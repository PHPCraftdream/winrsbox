// F1 (R04) decision seams for the ShellExecute* hooks — moved verbatim from
// mod.rs to keep that file under the winrsbox-layout-guard size limit. The
// detour hook bodies and the whole classifier chain stay in mod.rs; the
// seams are re-imported there (`use decide::{...}`) and reach tests.rs via
// its `use super::*` glob.

use winapi::ctypes::c_void;
use winapi::shared::minwindef::HINSTANCE;

use crate::anti_rec;
use crate::hooks::is_trace;

use super::{
    SE_ERR_ACCESSDENIED, SHELLEXECUTEINFOA, SHELLEXECUTEINFOW, shell_deny_reason,
    shell_fmask_deny_reason,
};
use super::inspect::{read_lpcstr, read_lpcwstr, uninspected_deny_reason};

/// F1 (R04) decision seam for `hook_shell_execute_w`: the ENTIRE decision
/// phase — string reads, fail-closed inspection, classifier chain, deny-path
/// violation log — runs under an anti_rec window this function opens and
/// closes. The hook invokes the real ShellExecuteW only AFTER this returns,
/// so shell verb handlers it dispatches run with hooks live: a nested hooked
/// call from that guest-reachable code gets a fresh policy check instead of
/// stale suppression (anti_rec invariant 3).
///
/// Returns `true` when the call is denied (the violation was already logged
/// in-window). `false` means the original must be invoked; this includes the
/// re-entrancy passthrough — when an outer hook window is already held on
/// this thread (`anti_rec::enter()` returns `None`) this returns `false`
/// unchecked, so the original still runs under that outer window exactly as
/// before the split.
///
/// # SAFETY
/// Each pointer must be null or readable memory (wild pointers are
/// probe-guarded and yield `Absent`, never a fault we propagate).
pub(super) unsafe fn shell_execute_w_deny(
    lp_operation: *const u16,
    lp_file: *const u16,
    lp_parameters: *const u16,
) -> bool {
    let Some(_guard) = anti_rec::enter() else {
        return false;
    };

    // Read all three attacker-supplied strings as `InspectedStr` — including
    // `lp_operation` (the verb), which the old hook never read at all, so a
    // `runas` verb bypassed every check. An argument with no NUL within
    // `MAX_TARGET_CHARS` comes back as `Unterminated` instead of a silently
    // truncated string.
    let verb = read_lpcwstr(lp_operation);
    let file = read_lpcwstr(lp_file);
    let params = read_lpcwstr(lp_parameters);

    // Fail closed FIRST: an argument the hook could not fully inspect must
    // refuse the whole call — a truncated view would let anything past the
    // cutoff evade every classifier below. Only when all three arguments
    // are fully inspected are they flattened via `as_deref()` and handed
    // to the classifier chain.
    let deny_reason = match uninspected_deny_reason(&verb, &file, &params) {
        Some(reason) => Some(reason),
        None => shell_deny_reason(verb.as_deref(), file.as_deref(), params.as_deref()),
    };
    if let Some(reason) = deny_reason {
        if is_trace() {
            let (verb_str, file_str, params_str) =
                (verb.as_deref(), file.as_deref(), params.as_deref());
            crate::hooks::ipc_log_violation(ipc::Req::Log {
                pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                level: ipc::LogLevel::Warn,
                msg: format!(
                    "shell_execute_blocked reason={reason} verb={verb_str} file={file_str} params={params_str}"
                ),
            });
        }
        return true;
    }
    false
}

/// F1 (R04) decision seam for `hook_shell_execute_ex_w`: the ENTIRE decision
/// phase — cbSize validation, string reads, fail-closed inspection, the F2
/// (R04) `fMask` alternate-resolution classification, classifier chain,
/// deny-path violation log and the `hInstApp` write — runs
/// under an anti_rec window this function opens and closes. The hook invokes
/// the real ShellExecuteExW only AFTER this returns, so shell verb handlers
/// it dispatches run with hooks live: a nested hooked call from that
/// guest-reachable code gets a fresh policy check instead of stale
/// suppression (anti_rec invariant 3).
///
/// Returns `true` when the call is denied (the violation was already logged
/// in-window). `false` means the original must be invoked; this includes the
/// re-entrancy passthrough — when an outer hook window is already held on
/// this thread (`anti_rec::enter()` returns `None`) this returns `false`
/// unchecked, so the original still runs under that outer window exactly as
/// before the split — and the cbSize fallthrough for a struct too small to
/// inspect (the real API rejects it itself).
///
/// # SAFETY
/// `p_exec_info` must be null or point to readable memory whose `cbSize`
/// field (offset 0) the caller initialized per the ABI contract; reads stay
/// within the prefix the declared `cbSize` proves, and `hInstApp` is written
/// only when `cbSize` covers the whole field.
pub(super) unsafe fn shell_execute_ex_w_deny(p_exec_info: *mut SHELLEXECUTEINFOW) -> bool {
    let Some(_guard) = anti_rec::enter() else {
        return false;
    };

    if !p_exec_info.is_null() {
        // Validate the caller-declared `cbSize` BEFORE we read past the
        // beginning of the struct or (on deny) write `hInstApp`. A caller that
        // passes a struct smaller than our mirror (e.g. an older/truncated
        // SHELLEXECUTEINFO) must not have `hInstApp` written into it — that
        // field sits near the end of the struct and writing it could clobber
        // memory past the caller's allocation.
        //
        // We compute the offset of `hInstApp` via `core::mem::offset_of!`
        // (stable since Rust 1.77) so this stays correct if the mirror layout
        // changes. A struct large enough to contain the whole `hInstApp` field
        // can be safely written; a smaller one is still DENIED (a malformed
        // struct must not get a free pass) but WITHOUT writing `hInstApp` — we
        // return FALSE only, which the caller can always observe.
        //
        // SAFETY: `p_exec_info` is non-null (checked above). Reading `cbSize`
        // (the first field, offset 0) is valid for any allocation a caller
        // could legitimately pass to ShellExecuteExW, which must contain at
        // least the `cbSize` field it is required to initialize.
        let cb_size = (*p_exec_info).cbSize as usize;
        const HINSTAPP_OFFSET: usize = core::mem::offset_of!(SHELLEXECUTEINFOW, hInstApp);
        // Bytes the caller must have allocated for a write of `hInstApp` to be
        // in-bounds: through the end of the field.
        let hinstapp_end = HINSTAPP_OFFSET + core::mem::size_of::<HINSTANCE>();
        // Bytes that must be present before we may read the prefix fields we
        // inspect. `lpParameters` is the last field we read, so its end is the
        // minimum struct size required for our reads to be in-bounds.
        const LPPARAMETERS_OFFSET: usize = core::mem::offset_of!(SHELLEXECUTEINFOW, lpParameters);
        let lpparameters_end = LPPARAMETERS_OFFSET + core::mem::size_of::<*const u16>();
        let cbsize_ok_for_full_struct = cb_size >= core::mem::size_of::<SHELLEXECUTEINFOW>();
        let cbsize_ok_for_hinstapp_write = cb_size >= hinstapp_end;

        // The target controls `cbSize`. If it declares a struct too small to
        // even contain the fields we inspect (`lpVerb`/`lpFile`/`lpParameters`),
        // reading those fields would touch memory past the caller's allocation. We
        // cannot inspect such a call, so fall through without a verdict — the
        // documented "can't inspect → call original" path. (We never deny on a
        // pointer we couldn't safely read; the real ShellExecuteExW will reject
        // a malformed `cbSize` itself.)
        if cb_size >= lpparameters_end {
            // SAFETY: `p_exec_info` is non-null (checked above) and `cb_size` is at
            // least `lpparameters_end`, so the prefix fields up to and including
            // `lpParameters` lie within the caller-declared (and per the ABI
            // contract, initialized) allocation. We only read those prefix fields;
            // the denylist/Unicode/params decision itself never writes the struct.
            let info_ref = &*p_exec_info;
            // Reading `lpVerb` is safe under the EXISTING `cb_size >=
            // lpparameters_end` guard: `offset_of!(lpVerb)` < `offset_of!(lpParameters)`,
            // so `lpVerb` lies within the same caller-declared allocation that
            // guard already proves covers every field up to and including
            // `lpParameters`. The old hook never read it, so a `runas` verb
            // bypassed every check.
            let verb = read_lpcwstr(info_ref.lpVerb);
            let file = read_lpcwstr(info_ref.lpFile);
            let params = read_lpcwstr(info_ref.lpParameters);
            // F2: `fMask` sits at offset 4 — proven in-bounds by the
            // `cb_size >= lpparameters_end` guard above.
            let f_mask = info_ref.fMask;

            // Fail closed FIRST: an argument the hook could not fully inspect
            // (no NUL within `MAX_TARGET_CHARS`) must refuse the whole call —
            // a truncated view would let anything past the cutoff evade every
            // classifier. Only when all three arguments are fully inspected are
            // they flattened via `as_deref()` and handed to the classifier chain.
            // F2 precedence: the fMask alternate-resolution check comes next —
            // WHICH struct member the shell resolves the target from is the
            // more fundamental fact than what the strings say — and only a
            // fully inspected call with a resolution-preserving mask reaches
            // the string chain.
            let deny_reason = match uninspected_deny_reason(&verb, &file, &params) {
                Some(reason) => Some(reason),
                None => match shell_fmask_deny_reason(info_ref.fMask) {
                    Some(reason) => Some(reason),
                    None => shell_deny_reason(verb.as_deref(), file.as_deref(), params.as_deref()),
                },
            };
            if let Some(reason) = deny_reason {
                // Note when the struct is too small to hold a full SHELLEXECUTEINFOW
                // so the log records why we may have skipped the hInstApp write.
                let truncated = !cbsize_ok_for_full_struct;
                if is_trace() {
                    let (verb_str, file_str, params_str) =
                        (verb.as_deref(), file.as_deref(), params.as_deref());
                    crate::hooks::ipc_log_violation(ipc::Req::Log {
                        pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                        level: ipc::LogLevel::Warn,
                        msg: format!(
                            "shell_execute_ex_blocked reason={reason} cbSize={cb_size} truncated={truncated} fMask={f_mask:#010x} verb={verb_str} file={file_str} params={params_str}"
                        ),
                    });
                }
                if cbsize_ok_for_hinstapp_write {
                    // Report SE_ERR_ACCESSDENIED via hInstApp per shellapi.h
                    // contract; the hook turns this verdict into FALSE.
                    // SAFETY: p_exec_info is non-null and the caller declared a
                    // `cbSize` (>= hinstapp_end) large enough to contain the whole
                    // `hInstApp` field, so this write is in-bounds.
                    (*p_exec_info).hInstApp = SE_ERR_ACCESSDENIED as *mut c_void as HINSTANCE;
                }
                // Deny regardless: a struct too small to hold `hInstApp` is still
                // refused (the hook returns FALSE) without the write.
                return true;
            }
        }
    }

    false
}

/// Full deny decision for one ShellExecuteA / ShellExecuteExA call, from raw
/// ANSI pointers to the classifier-chain verdict. Identical to the W path:
/// read + inspect all three attacker strings via `read_lpcstr`, fail closed
/// on any uninspected argument, then run the F2 `shell_fmask_deny_reason`
/// mask check, then the shared `shell_deny_reason`
/// chain (verb allowlist -> file denylist -> unicode-scheme -> params scan).
/// Returns the reason tag, or `None` when the call may proceed.
///
/// `f_mask` is the caller's `SHELLEXECUTEINFOA.fMask` for the ExA entry;
/// the plain `ShellExecuteA` entry passes `0` — that API takes no mask
/// parameter, so no fMask classification can apply.
///
/// Pure over its inputs (reads are bounded and probe-guarded); tests
/// fabricate ANSI buffers and drive exactly the decision the hooks apply —
/// no shell32 involvement.
///
/// # SAFETY
/// Each pointer must be null or readable memory (wild pointers are
/// probe-guarded and yield `Absent`, never a fault we propagate).
pub(super) unsafe fn shell_execute_a_deny_reason(
    lp_operation: *const u8,
    lp_file: *const u8,
    lp_parameters: *const u8,
    f_mask: u32,
) -> Option<&'static str> {
    let verb = read_lpcstr(lp_operation);
    let file = read_lpcstr(lp_file);
    let params = read_lpcstr(lp_parameters);
    match uninspected_deny_reason(&verb, &file, &params) {
        Some(reason) => Some(reason),
        None => match shell_fmask_deny_reason(f_mask) {
            Some(reason) => Some(reason),
            None => shell_deny_reason(verb.as_deref(), file.as_deref(), params.as_deref()),
        },
    }
}

/// F1 (R04) decision seam for `hook_shell_execute_a`: the ENTIRE decision
/// phase — `shell_execute_a_deny_reason` (string reads, fail-closed
/// inspection, classifier chain) plus the deny-path violation log — runs
/// under an anti_rec window this function opens and closes. The hook invokes
/// the real ShellExecuteA only AFTER this returns, so shell verb handlers it
/// dispatches run with hooks live: a nested hooked call from that
/// guest-reachable code gets a fresh policy check instead of stale
/// suppression (anti_rec invariant 3).
///
/// Returns `true` when the call is denied (the violation was already logged
/// in-window). `false` means the original must be invoked; this includes the
/// re-entrancy passthrough — when an outer hook window is already held on
/// this thread (`anti_rec::enter()` returns `None`) this returns `false`
/// unchecked, so the original still runs under that outer window exactly as
/// before the split.
///
/// # SAFETY
/// Each pointer must be null or readable memory (wild pointers are
/// probe-guarded and yield `Absent`, never a fault we propagate).
pub(super) unsafe fn shell_execute_a_deny(
    lp_operation: *const u8,
    lp_file: *const u8,
    lp_parameters: *const u8,
) -> bool {
    let Some(_guard) = anti_rec::enter() else {
        return false;
    };
    // Plain ShellExecuteA takes no fMask parameter — pass 0 so the F2
    // mask classification (Ex-only) cannot fire.
    if let Some(reason) = shell_execute_a_deny_reason(lp_operation, lp_file, lp_parameters, 0) {
        if is_trace() {
            crate::hooks::ipc_log_violation(ipc::Req::Log {
                pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                level: ipc::LogLevel::Warn,
                msg: format!("shell_execute_a_blocked reason={reason}"),
            });
        }
        return true;
    }
    false
}

/// F1 (R04) decision seam for `hook_shell_execute_ex_a`: the ENTIRE decision
/// phase — cbSize validation, string reads via `shell_execute_a_deny_reason`
/// (which since F2 (R04) also runs the fMask classification on the caller's
/// `fMask`), deny-path violation log and the `hInstApp` write — runs under an anti_rec
/// window this function opens and closes. The hook invokes the real
/// ShellExecuteExA only AFTER this returns, so shell verb handlers it
/// dispatches run with hooks live: a nested hooked call from that
/// guest-reachable code gets a fresh policy check instead of stale
/// suppression (anti_rec invariant 3).
///
/// Returns `true` when the call is denied (the violation was already logged
/// in-window). `false` means the original must be invoked; this includes the
/// re-entrancy passthrough — when an outer hook window is already held on
/// this thread (`anti_rec::enter()` returns `None`) this returns `false`
/// unchecked, so the original still runs under that outer window exactly as
/// before the split — and the cbSize fallthrough for a struct too small to
/// inspect (the real API rejects it itself).
///
/// # SAFETY
/// `p_exec_info` must be null or point to readable memory whose `cbSize`
/// field (offset 0) the caller initialized per the ABI contract; reads stay
/// within the prefix the declared `cbSize` proves, and `hInstApp` is written
/// only when `cbSize` covers the whole field.
pub(super) unsafe fn shell_execute_ex_a_deny(p_exec_info: *mut SHELLEXECUTEINFOA) -> bool {
    let Some(_guard) = anti_rec::enter() else {
        return false;
    };

    if !p_exec_info.is_null() {
        // cbSize validation identical to the W hook: a struct too small to
        // contain the inspected prefix falls through to the original (the
        // real API rejects it), and hInstApp is only written when the
        // caller's declared size proves the field exists.
        // SAFETY: p_exec_info is non-null (checked above); reading cbSize
        // (offset 0) is valid for any allocation a caller could legitimately
        // pass, since cbSize is the field it is required to initialize.
        let cb_size = (*p_exec_info).cbSize as usize;
        const HINSTAPP_OFFSET_A: usize = core::mem::offset_of!(SHELLEXECUTEINFOA, hInstApp);
        let hinstapp_end = HINSTAPP_OFFSET_A + core::mem::size_of::<HINSTANCE>();
        const LPPARAMETERS_OFFSET_A: usize = core::mem::offset_of!(SHELLEXECUTEINFOA, lpParameters);
        let lpparameters_end = LPPARAMETERS_OFFSET_A + core::mem::size_of::<*const u8>();
        let cbsize_ok_for_full_struct = cb_size >= core::mem::size_of::<SHELLEXECUTEINFOA>();
        let cbsize_ok_for_hinstapp_write = cb_size >= hinstapp_end;

        if cb_size >= lpparameters_end {
            // SAFETY: cb_size >= lpparameters_end proves the prefix fields up to
            // and including lpParameters lie within the caller's allocation.
            let info_ref = &*p_exec_info;
            // F2: `fMask` sits at offset 4 — in-bounds under the same guard.
            let f_mask = info_ref.fMask;
            let deny_reason = shell_execute_a_deny_reason(
                info_ref.lpVerb, info_ref.lpFile, info_ref.lpParameters, f_mask,
            );
            if let Some(reason) = deny_reason {
                let truncated = !cbsize_ok_for_full_struct;
                if is_trace() {
                    crate::hooks::ipc_log_violation(ipc::Req::Log {
                        pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                        level: ipc::LogLevel::Warn,
                        msg: format!(
                            "shell_execute_ex_a_blocked reason={reason} cbSize={cb_size} truncated={truncated} fMask={f_mask:#010x}"
                        ),
                    });
                }
                if cbsize_ok_for_hinstapp_write {
                    // Report SE_ERR_ACCESSDENIED via hInstApp; the hook turns
                    // this verdict into FALSE.
                    // SAFETY: p_exec_info is non-null and the caller declared a
                    // cbSize (>= hinstapp_end) covering the whole hInstApp field.
                    (*p_exec_info).hInstApp = SE_ERR_ACCESSDENIED as *mut c_void as HINSTANCE;
                }
                // Denied regardless: a struct too small for hInstApp is refused
                // (the hook returns FALSE) without the write.
                return true;
            }
        }
    }

    false
}
