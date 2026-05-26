// Process Mitigation Policies — kernel-enforced restrictions applied via
// PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY at CreateProcess time.
//
// Pure computation module: builds u64 bitmask from guard profile.
// No Windows API calls here — those live in main.rs launch path.

/// Mitigation policy v1 flags (first DWORD64).
pub mod v1 {
    pub const DEP_ENABLE: u64                             = 0x01 << 36;
    pub const DEP_ATL_THUNK_ENABLE: u64                   = 0x01 << 40;
    pub const SEHOP_ENABLE: u64                           = 0x01 << 44;
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
    pub const RESTRICT_INDIRECT_BRANCH_PREDICTION: u64        = 0x01 << 16;
    pub const SPECULATIVE_STORE_BYPASS_DISABLE: u64           = 0x01 << 24;
    pub const CET_USER_SHADOW_STACKS_ALWAYS_ON: u64           = 0x01 << 40;
    pub const CET_USER_SHADOW_STACKS_STRICT_MODE: u64         = 0x01 << 42;
    pub const BLOCK_NON_CET_BINARIES_ALWAYS_ON: u64           = 0x01 << 52;
    pub const XTENDED_CONTROL_FLOW_GUARD_ALWAYS_ON: u64       = 0x01 << 56;
}

/// Guard profile as consumed by mitigations module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    None,
    Scan,
    Full,
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
            let m1 = v1::PROHIBIT_DYNAMIC_CODE_ALWAYS_ON
                   | v1::BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
                   | v1::EXTENSION_POINT_DISABLE_ALWAYS_ON
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
    fn full_includes_dynamic_code_prohibition() {
        let (m1, _) = compute(Profile::Full);
        assert_ne!(m1 & v1::PROHIBIT_DYNAMIC_CODE_ALWAYS_ON, 0);
    }

    #[test]
    fn full_includes_block_non_ms() {
        let (m1, _) = compute(Profile::Full);
        assert_ne!(m1 & v1::BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON, 0);
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
}
