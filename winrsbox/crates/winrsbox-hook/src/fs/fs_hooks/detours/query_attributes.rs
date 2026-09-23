use super::*;

pub(crate) unsafe extern "system" fn hook_nt_query_attributes_file(
    object_attributes: *mut OBJECT_ATTRIBUTES,
    file_information: *mut c_void,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return nt_call_original!(
            &HOOK_NT_QUERY_ATTRIBUTES_FILE,
            "NtQueryAttributesFile",
            (object_attributes, file_information)
        );
    };

    // H5 resolve-once.
    let Some((dos, pre_resolved)) = resolve_for_hook(object_attributes as *const _) else {
        return nt_call_original!(
            &HOOK_NT_QUERY_ATTRIBUTES_FILE,
            "NtQueryAttributesFile",
            (object_attributes, file_information)
        );
    };

    let mut decision = decide(&dos, false);
    // C04 (docs/review-xa-2026-09-20): a locally cached Cow whose overlay
    // target vanished (sibling deleted it + recorded a whiteout) must be
    // re-decided fresh before this hook trusts it.
    decision = decide_fresh_if_overlay_missing(&decision, &dos, false);
    if is_trace() {
        ipc_log(ipc::LogLevel::Trace, format!("fs_decide NtQueryAttributesFile: {dos} write=false mode={:?}", decision.mode));
    }
    match decision.mode {
        Mode::Hidden => STATUS_OBJECT_NAME_NOT_FOUND,
        Mode::Passthrough => {
            // SAFETY: object_attributes is non-null.
            let mut copy = match HookedAttrs::copy_passthrough_inner(
                &*object_attributes, pre_resolved.as_deref()
            ) {
                Some(c) => c,
                None => {
                    // Oversized / unresolvable path — fail CLOSED (audit H5).
                    if is_trace() {
                        crate::ipc_client::ipc_log_violation(ipc::Req::Log {
                            pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                            level: ipc::LogLevel::Warn,
                            msg: "passthrough_copy_failed_fail_closed".to_string(),
                        });
                    }
                    return STATUS_ACCESS_DENIED;
                }
            };
            let attrs_ptr = copy.as_ptr_mut();
            nt_call_original!(
                &HOOK_NT_QUERY_ATTRIBUTES_FILE,
                "NtQueryAttributesFile",
                (attrs_ptr, file_information)
            )
        }
        Mode::Deny => STATUS_ACCESS_DENIED,
        Mode::Mock => {
            // Malformed Mock — fail CLOSED like the create/open arms. A query
            // fall-through would report the REAL file's attributes for a path
            // policy decided to mock (unlike the Cow arm below, an incomplete
            // Mock is corruption of the decision, not a pre-write state).
            let Some(ref overlay_path) = decision.overlay else {
                crate::ipc_client::ipc_log_violation(ipc::Req::Log {
                    pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                    level: ipc::LogLevel::Warn,
                    msg: format!("mock_malformed_decision_deny query_attributes no_overlay: {dos}"),
                });
                return STATUS_ACCESS_DENIED;
            };
            // If overlay missing, materialize mock payload first so the
            // redirected query observes the mocked file instead of ENOENT.
            if !overlay_path.exists() {
                if let Some(ref payload) = decision.mock_payload {
                    materialize_mock_overlay(overlay_path, payload);
                } else {
                    crate::ipc_client::ipc_log_violation(ipc::Req::Log {
                        pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                        level: ipc::LogLevel::Warn,
                        msg: format!("mock_malformed_decision_deny query_attributes no_payload: {dos}"),
                    });
                    return STATUS_ACCESS_DENIED;
                }
            }
            let overlay_dos = overlay_path.to_string_lossy().into_owned();
            // Query path: keep orig's SQOS verbatim (NtQueryAttributesFile is
            // not a create/open syscall and does not exhibit the SQOS
            // STATUS_INVALID_PARAMETER quirk).
            // SAFETY: object_attributes is non-null.
            let mut h = HookedAttrs::redirect(&*object_attributes, &overlay_dos, false);
            nt_call_original!(
                &HOOK_NT_QUERY_ATTRIBUTES_FILE,
                "NtQueryAttributesFile",
                (h.as_ptr_mut(), file_information)
            )
        }
        Mode::Cow => {
            // Design choice: for read-only Query hooks we fall through to the
            // original path when overlay is missing (or the field itself is
            // None). Querying the original is benign — it merely reports
            // attributes; any actual write/open will hit hook_nt_create_file /
            // hook_nt_open_file which fail-close on Mode::Cow + overlay=None.
            // Returning STATUS_OBJECT_NAME_NOT_FOUND here would break
            // legitimate stat-then-open patterns where callers probe a file
            // first; the write-side is the actual security boundary.
            // C04: with the fresh re-check above, a whiteouted path's fresh
            // decide is Hidden → NOT_FOUND is now returned here too (correct
            // merged view); only a genuinely-not-yet-copied Cow (fresh decide
            // still Cow) keeps the fall-through so stat-then-open keeps working.
            let Some(ref overlay_path) = decision.overlay else {
                return nt_call_original!(
                    &HOOK_NT_QUERY_ATTRIBUTES_FILE,
                    "NtQueryAttributesFile",
                    (object_attributes, file_information)
                );
            };
            if !overlay_path.exists() {
                return nt_call_original!(
                    &HOOK_NT_QUERY_ATTRIBUTES_FILE,
                    "NtQueryAttributesFile",
                    (object_attributes, file_information)
                );
            }
            let overlay_dos = overlay_path.to_string_lossy().into_owned();
            // SAFETY: object_attributes is non-null.
            let mut h = HookedAttrs::redirect(&*object_attributes, &overlay_dos, false);
            nt_call_original!(
                &HOOK_NT_QUERY_ATTRIBUTES_FILE,
                "NtQueryAttributesFile",
                (h.as_ptr_mut(), file_information)
            )
        }
    }
}

pub(crate) unsafe extern "system" fn hook_nt_query_full_attributes_file(
    object_attributes: *mut OBJECT_ATTRIBUTES,
    file_information: *mut c_void,
) -> NTSTATUS {
    let Some(_guard) = anti_rec::enter() else {
        return nt_call_original!(
            &HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE,
            "NtQueryFullAttributesFile",
            (object_attributes, file_information)
        );
    };

    // H5 resolve-once.
    let Some((dos, pre_resolved)) = resolve_for_hook(object_attributes as *const _) else {
        return nt_call_original!(
            &HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE,
            "NtQueryFullAttributesFile",
            (object_attributes, file_information)
        );
    };

    let mut decision = decide(&dos, false);
    // C04 (docs/review-xa-2026-09-20): a locally cached Cow whose overlay
    // target vanished (sibling deleted it + recorded a whiteout) must be
    // re-decided fresh before this hook trusts it.
    decision = decide_fresh_if_overlay_missing(&decision, &dos, false);
    if is_trace() {
        ipc_log(ipc::LogLevel::Trace, format!("fs_decide NtQueryFullAttributesFile: {dos} write=false mode={:?}", decision.mode));
    }
    match decision.mode {
        Mode::Hidden => STATUS_OBJECT_NAME_NOT_FOUND,
        Mode::Passthrough => {
            // SAFETY: object_attributes is non-null.
            let mut copy = match HookedAttrs::copy_passthrough_inner(
                &*object_attributes, pre_resolved.as_deref()
            ) {
                Some(c) => c,
                None => {
                    // Oversized / unresolvable path — fail CLOSED (audit H5).
                    if is_trace() {
                        crate::ipc_client::ipc_log_violation(ipc::Req::Log {
                            pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                            level: ipc::LogLevel::Warn,
                            msg: "passthrough_copy_failed_fail_closed".to_string(),
                        });
                    }
                    return STATUS_ACCESS_DENIED;
                }
            };
            let attrs_ptr = copy.as_ptr_mut();
            nt_call_original!(
                &HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE,
                "NtQueryFullAttributesFile",
                (attrs_ptr, file_information)
            )
        }
        Mode::Deny => STATUS_ACCESS_DENIED,
        Mode::Mock => {
            // Malformed Mock — fail CLOSED, same rationale as
            // hook_nt_query_attributes_file's Mock arm.
            let Some(ref overlay_path) = decision.overlay else {
                crate::ipc_client::ipc_log_violation(ipc::Req::Log {
                    pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                    level: ipc::LogLevel::Warn,
                    msg: format!("mock_malformed_decision_deny query_full no_overlay: {dos}"),
                });
                return STATUS_ACCESS_DENIED;
            };
            // If overlay missing, materialize mock payload first so the
            // redirected query observes the mocked file instead of ENOENT.
            if !overlay_path.exists() {
                if let Some(ref payload) = decision.mock_payload {
                    materialize_mock_overlay(overlay_path, payload);
                } else {
                    crate::ipc_client::ipc_log_violation(ipc::Req::Log {
                        pid: winapi::um::processthreadsapi::GetCurrentProcessId(),
                        level: ipc::LogLevel::Warn,
                        msg: format!("mock_malformed_decision_deny query_full no_payload: {dos}"),
                    });
                    return STATUS_ACCESS_DENIED;
                }
            }
            let overlay_dos = overlay_path.to_string_lossy().into_owned();
            // SAFETY: object_attributes is non-null.
            let mut h = HookedAttrs::redirect(&*object_attributes, &overlay_dos, false);
            nt_call_original!(
                &HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE,
                "NtQueryFullAttributesFile",
                (h.as_ptr_mut(), file_information)
            )
        }
        Mode::Cow => {
            // See hook_nt_query_attributes_file for the read-only fall-through
            // rationale. Write-side fail-close lives in create/open hooks.
            // C04: with the fresh re-check above, a whiteouted path's fresh
            // decide is Hidden → NOT_FOUND is returned here too; only a
            // genuinely-not-yet-copied Cow keeps this fall-through.
            let Some(ref overlay_path) = decision.overlay else {
                return nt_call_original!(
                    &HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE,
                    "NtQueryFullAttributesFile",
                    (object_attributes, file_information)
                );
            };
            if !overlay_path.exists() {
                return nt_call_original!(
                    &HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE,
                    "NtQueryFullAttributesFile",
                    (object_attributes, file_information)
                );
            }
            let overlay_dos = overlay_path.to_string_lossy().into_owned();
            // SAFETY: object_attributes is non-null.
            let mut h = HookedAttrs::redirect(&*object_attributes, &overlay_dos, false);
            nt_call_original!(
                &HOOK_NT_QUERY_FULL_ATTRIBUTES_FILE,
                "NtQueryFullAttributesFile",
                (h.as_ptr_mut(), file_information)
            )
        }
    }
}
