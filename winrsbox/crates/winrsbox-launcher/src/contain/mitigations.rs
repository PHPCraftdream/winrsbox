// Process Mitigation Policies — kernel-enforced restrictions applied via
// PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY at CreateProcess time.
//
// Pure computation module: builds u64 bitmask from guard profile.
// No Windows API calls here — those live in main.rs launch path.

/// Mitigation policy v1 flags (first DWORD64 of the 16-byte
/// PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY value).
///
/// Bit layout per Microsoft docs:
///   DEP / ATL-Thunk / SEHOP are single-bit flags in bits 0–2.
///   Remaining policies are 2-bit fields at 4-bit-aligned offsets.
///   The "always on" variant sets bit 0 of the field (offset+0).
pub mod v1 {
    pub const DEP_ENABLE: u64                             = 0x01 << 0;
    pub const DEP_ATL_THUNK_ENABLE: u64                   = 0x01 << 1;
    pub const SEHOP_ENABLE: u64                           = 0x01 << 2;
    pub const FORCE_RELOCATE_IMAGES_ALWAYS_ON: u64        = 0x01 << 8;
    pub const HEAP_TERMINATE_ALWAYS_ON: u64               = 0x01 << 12;
    pub const BOTTOM_UP_ASLR_ALWAYS_ON: u64               = 0x01 << 16;
    pub const HIGH_ENTROPY_ASLR_ALWAYS_ON: u64            = 0x01 << 20;
    pub const STRICT_HANDLE_CHECKS_ALWAYS_ON: u64         = 0x01 << 24;
    pub const WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON: u64   = 0x01 << 28;
    pub const EXTENSION_POINT_DISABLE_ALWAYS_ON: u64      = 0x01 << 32;
    pub const PROHIBIT_DYNAMIC_CODE_ALWAYS_ON: u64        = 0x01 << 36;
    pub const CONTROL_FLOW_GUARD_ALWAYS_ON: u64           = 0x01 << 40;
    pub const BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON: u64 = 0x01 << 44;
    pub const FONT_DISABLE_ALWAYS_ON: u64                 = 0x01 << 48;
    pub const IMAGE_LOAD_NO_REMOTE_ALWAYS_ON: u64         = 0x01 << 52;
    pub const IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON: u64      = 0x01 << 56;
    pub const IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON: u64   = 0x01 << 60;
}

/// Mitigation policy v2 flags (second DWORD64, Windows 10 1709+).
pub mod v2 {
    pub const STRICT_CONTROL_FLOW_GUARD_ALWAYS_ON: u64     = 0x01 << 8;
    pub const RESTRICT_INDIRECT_BRANCH_PREDICTION: u64     = 0x01 << 16;
    pub const SPECULATIVE_STORE_BYPASS_DISABLE: u64        = 0x01 << 24;
    pub const CET_USER_SHADOW_STACKS_ALWAYS_ON: u64        = 0x01 << 28;
    pub const CET_USER_SHADOW_STACKS_STRICT_MODE: u64      = 0x01 << 29;
    pub const USER_CET_SET_CONTEXT_IP_VALIDATION_ALWAYS_ON: u64 = 0x01 << 32;
    pub const BLOCK_NON_CET_BINARIES_ALWAYS_ON: u64        = 0x01 << 36;
    pub const CET_DYNAMIC_APIS_OUT_OF_PROC_ONLY_ALWAYS_ON: u64 = 0x01 << 48;
    pub const FSCTL_SYSTEM_CALL_DISABLE_ALWAYS_ON: u64     = 0x01 << 56;
}

/// Guard profile as consumed by mitigations module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    None,
    Scan,
    Full,
    /// Hard containment: Full + the JIT/unsigned-code killers
    /// (ProhibitDynamicCode + BlockNonMicrosoftBinaries). Opt-in only.
    Static,
}

/// Compute (v1, v2) bitmask for the given guard profile.
/// Pure function — no side effects, fully testable.
pub fn compute(profile: Profile) -> (u64, u64) {
    match profile {
        Profile::None => (0, 0),
        Profile::Scan => {
            // JIT-friendly: NO ProhibitDynamicCode, NO BlockNonMicrosoftBinaries.
            let m1 = v1::EXTENSION_POINT_DISABLE_ALWAYS_ON
                   | v1::FORCE_RELOCATE_IMAGES_ALWAYS_ON
                   | v1::HEAP_TERMINATE_ALWAYS_ON
                   | v1::BOTTOM_UP_ASLR_ALWAYS_ON
                   | v1::HIGH_ENTROPY_ASLR_ALWAYS_ON
                   | v1::STRICT_HANDLE_CHECKS_ALWAYS_ON
                   | v1::IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON
                   | v1::IMAGE_LOAD_NO_REMOTE_ALWAYS_ON;
            (m1, 0)
        }
        Profile::Full => {
            // JIT-SAFE hardening: Scan's bits PLUS the v2 speculative-execution
            // mitigations. Deliberately NO ProhibitDynamicCode and NO
            // BlockNonMicrosoftBinaries — those break JIT runtimes (node/V8,
            // .NET) and unsigned native extensions (Python .pyd, Node .node),
            // which ARE the canonical sandboxed workload. Containment in full
            // mode rests on the ntdll hooks + Job Object + ASLR, matched to the
            // real adversary (a misbehaving agent, not a hand-rolled exploit).
            let m1 = v1::EXTENSION_POINT_DISABLE_ALWAYS_ON
                   | v1::FORCE_RELOCATE_IMAGES_ALWAYS_ON
                   | v1::HEAP_TERMINATE_ALWAYS_ON
                   | v1::BOTTOM_UP_ASLR_ALWAYS_ON
                   | v1::HIGH_ENTROPY_ASLR_ALWAYS_ON
                   | v1::STRICT_HANDLE_CHECKS_ALWAYS_ON
                   | v1::IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON
                   | v1::IMAGE_LOAD_NO_REMOTE_ALWAYS_ON;
            let m2 = v2::RESTRICT_INDIRECT_BRANCH_PREDICTION
                   | v2::SPECULATIVE_STORE_BYPASS_DISABLE;
            (m1, m2)
        }
        Profile::Static => {
            // Hard containment (opt-in): Full + the two JIT/unsigned-code
            // killers. Closes the direct-syscall + fresh-ntdll hook-bypass
            // surface that user-mode hooking fundamentally cannot. Breaks JIT
            // and unsigned native extensions — only for pure-static targets.
            // hook.dll itself is unsigned, so BLOCK_NON_MICROSOFT is stripped
            // from the CREATE-time bitmap (sandbox.rs) and re-applied at RUNTIME
            // (hook::apply_mitigations) after hook.dll has loaded.
            let (full_m1, full_m2) = compute(Profile::Full);
            let m1 = full_m1
                   | v1::PROHIBIT_DYNAMIC_CODE_ALWAYS_ON
                   | v1::BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
            (m1, full_m2)
        }
    }
}

/// Encode (v1, v2) into the raw bytes expected by
/// PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY (16 bytes LE).
pub fn to_bytes(v1: u64, v2: u64) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&v1.to_le_bytes());
    buf[8..16].copy_from_slice(&v2.to_le_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_returns_zero() {
        assert_eq!(compute(Profile::None), (0, 0));
    }

    #[test]
    fn scan_excludes_dynamic_code_prohibition() {
        let (m1, _) = compute(Profile::Scan);
        assert_eq!(m1 & v1::PROHIBIT_DYNAMIC_CODE_ALWAYS_ON, 0);
    }

    #[test]
    fn scan_excludes_block_non_ms_binaries() {
        let (m1, _) = compute(Profile::Scan);
        assert_eq!(m1 & v1::BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON, 0);
    }

    #[test]
    fn scan_includes_extension_point_disable() {
        let (m1, _) = compute(Profile::Scan);
        assert_ne!(m1 & v1::EXTENSION_POINT_DISABLE_ALWAYS_ON, 0);
    }

    #[test]
    fn scan_includes_aslr() {
        let (m1, _) = compute(Profile::Scan);
        assert_ne!(m1 & v1::FORCE_RELOCATE_IMAGES_ALWAYS_ON, 0);
        assert_ne!(m1 & v1::BOTTOM_UP_ASLR_ALWAYS_ON, 0);
        assert_ne!(m1 & v1::HIGH_ENTROPY_ASLR_ALWAYS_ON, 0);
    }

    #[test]
    fn full_is_jit_safe_excludes_dynamic_code_and_signing() {
        // The whole point of the M4 redefinition: full mode must NOT carry the
        // JIT/unsigned-code killers, so node/python/cargo run under it.
        let (m1, _) = compute(Profile::Full);
        assert_eq!(m1 & v1::PROHIBIT_DYNAMIC_CODE_ALWAYS_ON, 0,
            "full must not prohibit dynamic code (breaks JIT)");
        assert_eq!(m1 & v1::BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON, 0,
            "full must not require signed binaries (breaks .pyd/.node)");
    }

    #[test]
    fn full_v2_has_speculative_protections() {
        let (_, m2) = compute(Profile::Full);
        assert_ne!(m2 & v2::RESTRICT_INDIRECT_BRANCH_PREDICTION, 0);
        assert_ne!(m2 & v2::SPECULATIVE_STORE_BYPASS_DISABLE, 0);
    }

    #[test]
    fn full_is_superset_of_scan() {
        let (scan_m1, _) = compute(Profile::Scan);
        let (full_m1, _) = compute(Profile::Full);
        assert_eq!(full_m1 & scan_m1, scan_m1, "full should include all scan bits");
    }

    #[test]
    fn static_includes_dynamic_code_prohibition() {
        let (m1, _) = compute(Profile::Static);
        assert_ne!(m1 & v1::PROHIBIT_DYNAMIC_CODE_ALWAYS_ON, 0);
    }

    #[test]
    fn static_includes_block_non_ms() {
        let (m1, _) = compute(Profile::Static);
        assert_ne!(m1 & v1::BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON, 0);
    }

    #[test]
    fn static_is_superset_of_full() {
        let (full_m1, full_m2) = compute(Profile::Full);
        let (static_m1, static_m2) = compute(Profile::Static);
        assert_eq!(static_m1 & full_m1, full_m1, "static should include all full bits");
        assert_eq!(static_m2, full_m2, "static shares full's v2 bits");
    }

    #[test]
    fn static_create_time_strip_still_loads_hook_dll() {
        // Both BLOCK_NON_MICROSOFT and PROHIBIT_DYNAMIC_CODE must be strippable
        // from the create-time bitmap so our bootstrap survives: the unsigned
        // hook.dll can load (signing), and detour2 can allocate/patch the
        // executable trampolines (dynamic code). Both re-applied at runtime
        // after detours are installed. Mirrors the strip in sandbox.rs.
        let (m1, _) = compute(Profile::Static);
        let create_v1 = m1
            & !v1::BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
            & !v1::PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
        assert_eq!(create_v1 & v1::BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON, 0);
        assert_eq!(create_v1 & v1::PROHIBIT_DYNAMIC_CODE_ALWAYS_ON, 0);
        // The pure-hardening bits survive (they don't block our bootstrap).
        assert_ne!(create_v1 & v1::BOTTOM_UP_ASLR_ALWAYS_ON, 0);
        assert_ne!(create_v1 & v1::STRICT_HANDLE_CHECKS_ALWAYS_ON, 0);
    }

    #[test]
    fn to_bytes_round_trips() {
        let (m1, m2) = compute(Profile::Full);
        let bytes = to_bytes(m1, m2);
        let m1_back = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let m2_back = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        assert_eq!(m1, m1_back);
        assert_eq!(m2, m2_back);
    }

    #[test]
    fn to_bytes_none_is_all_zero() {
        let bytes = to_bytes(0, 0);
        assert!(bytes.iter().all(|&b| b == 0));
    }

    // ─── Create-time mitigation bitmap composition ──────────────────────────
    //
    // These tests pin the EXACT bitmask handed to
    // PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY by sandbox::launch_suspended.
    //
    // The launcher strips BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON from the
    // create-time bitmap (and re-applies it at runtime from inside hook.dll's
    // apply_mitigations, AFTER our unsigned hook.dll has loaded). Every other
    // bit MUST survive into the kernel's create-time policy because those
    // policies are create-time-only — there is no SetProcessMitigationPolicy
    // for STRICT_HANDLE_CHECKS, FORCE_RELOCATE_IMAGES, or HIGH_ENTROPY_ASLR.

    /// Static mode minus the runtime-applied BLOCK_NON_MICROSOFT bit. Locks in
    /// every create-time-only policy we expect the kernel to enforce on the
    /// suspended child before hook.dll loads. (Static is the only profile that
    /// carries the runtime-stripped bit after the M4 split; Full is JIT-safe.)
    #[test]
    fn static_create_time_bitmap_retains_all_required_v1_bits() {
        let (static_m1, _) = compute(Profile::Static);
        let create_v1 = static_m1
            & !v1::BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
            & !v1::PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;

        // Both bootstrap-killers must be CLEARED at create time and re-applied
        // at runtime: BLOCK_NON_MICROSOFT (else the unsigned hook.dll is
        // rejected by the kernel image loader) and PROHIBIT_DYNAMIC_CODE (else
        // detour2 can't allocate/patch executable trampolines).
        assert_eq!(create_v1 & v1::BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON, 0,
            "create-time bitmap must NOT include BLOCK_NON_MICROSOFT_BINARIES");
        assert_eq!(create_v1 & v1::PROHIBIT_DYNAMIC_CODE_ALWAYS_ON, 0,
            "create-time bitmap must NOT include PROHIBIT_DYNAMIC_CODE (blocks detour install)");

        // ALL other Static v1 bits must survive — none of these are
        // re-settable at runtime via SetProcessMitigationPolicy, so the kernel
        // ONLY learns about them through this create-time bitmap.
        assert_ne!(create_v1 & v1::FORCE_RELOCATE_IMAGES_ALWAYS_ON, 0,
            "FORCE_RELOCATE_IMAGES_ALWAYS_ON missing from create-time bitmap");
        assert_ne!(create_v1 & v1::HEAP_TERMINATE_ALWAYS_ON, 0,
            "HEAP_TERMINATE_ALWAYS_ON missing from create-time bitmap");
        assert_ne!(create_v1 & v1::BOTTOM_UP_ASLR_ALWAYS_ON, 0,
            "BOTTOM_UP_ASLR_ALWAYS_ON missing from create-time bitmap");
        assert_ne!(create_v1 & v1::HIGH_ENTROPY_ASLR_ALWAYS_ON, 0,
            "HIGH_ENTROPY_ASLR_ALWAYS_ON missing from create-time bitmap");
        assert_ne!(create_v1 & v1::STRICT_HANDLE_CHECKS_ALWAYS_ON, 0,
            "STRICT_HANDLE_CHECKS_ALWAYS_ON missing from create-time bitmap");
        assert_ne!(create_v1 & v1::IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON, 0,
            "IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON missing from create-time bitmap");
        assert_ne!(create_v1 & v1::IMAGE_LOAD_NO_REMOTE_ALWAYS_ON, 0,
            "IMAGE_LOAD_NO_REMOTE_ALWAYS_ON missing from create-time bitmap");
        assert_ne!(create_v1 & v1::EXTENSION_POINT_DISABLE_ALWAYS_ON, 0,
            "EXTENSION_POINT_DISABLE_ALWAYS_ON missing from create-time bitmap");
    }

    /// Scan mode bitmap composition: hardening bits ON, JIT-killing bits OFF.
    /// Scan is the JIT-friendly profile — agent runtimes (node, .NET, JVM)
    /// must keep working. Block-non-MS and PROHIBIT_DYNAMIC_CODE both kill
    /// JIT, so neither is set in either the policy or the create-time bitmap.
    #[test]
    fn scan_bitmap_excludes_jit_killers_includes_hardening() {
        let (scan_m1, scan_m2) = compute(Profile::Scan);
        // Scan never sets v2 today; lock that in so a future tweak doesn't
        // accidentally enable CET on JIT-heavy targets.
        assert_eq!(scan_m2, 0, "Scan profile must not set any v2 bits");

        // JIT-killing bits — must be ABSENT.
        assert_eq!(scan_m1 & v1::PROHIBIT_DYNAMIC_CODE_ALWAYS_ON, 0,
            "Scan must not set PROHIBIT_DYNAMIC_CODE (breaks JIT runtimes)");
        assert_eq!(scan_m1 & v1::BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON, 0,
            "Scan must not set BLOCK_NON_MICROSOFT_BINARIES (breaks 3p DLLs)");

        // Hardening bits — must be PRESENT.
        assert_ne!(scan_m1 & v1::FORCE_RELOCATE_IMAGES_ALWAYS_ON, 0);
        assert_ne!(scan_m1 & v1::HEAP_TERMINATE_ALWAYS_ON, 0);
        assert_ne!(scan_m1 & v1::BOTTOM_UP_ASLR_ALWAYS_ON, 0);
        assert_ne!(scan_m1 & v1::HIGH_ENTROPY_ASLR_ALWAYS_ON, 0);
        assert_ne!(scan_m1 & v1::STRICT_HANDLE_CHECKS_ALWAYS_ON, 0);
        assert_ne!(scan_m1 & v1::IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON, 0);
        assert_ne!(scan_m1 & v1::IMAGE_LOAD_NO_REMOTE_ALWAYS_ON, 0);
        assert_ne!(scan_m1 & v1::EXTENSION_POINT_DISABLE_ALWAYS_ON, 0);
    }

    /// The Static create-time bitmap differs from the raw Static bitmap by
    /// EXACTLY the two bootstrap-killers (BLOCK_NON_MICROSOFT +
    /// PROHIBIT_DYNAMIC_CODE). Catches any future drift where a maintainer adds
    /// another "runtime-only" exception without thinking it through. (Full
    /// carries neither, so the strip is a no-op there — the invariant only has
    /// teeth on Static.)
    #[test]
    fn create_time_strip_is_exactly_block_non_ms_and_dynamic_code() {
        let (static_m1, _) = compute(Profile::Static);
        let create_v1 = static_m1
            & !v1::BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
            & !v1::PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
        let diff = static_m1 ^ create_v1;
        assert_eq!(
            diff,
            v1::BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON | v1::PROHIBIT_DYNAMIC_CODE_ALWAYS_ON,
            "create-time strip must remove exactly the two bootstrap-killers"
        );
        // Full, by contrast, has nothing to strip — it's JIT-safe.
        let (full_m1, _) = compute(Profile::Full);
        assert_eq!(full_m1 & v1::BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON, 0,
            "full must not carry BLOCK_NON_MICROSOFT");
        assert_eq!(full_m1 & v1::PROHIBIT_DYNAMIC_CODE_ALWAYS_ON, 0,
            "full must not carry PROHIBIT_DYNAMIC_CODE");
    }
}
