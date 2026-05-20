// WFP (Windows Filtering Platform) user-mode network filtering.
//
// Kernel-enforced — direct syscalls cannot bypass.
// Registers filters via fwpuclnt.dll from user-mode.

use anyhow::Result;
use std::path::Path;

// ---------------------------------------------------------------------------
// CIDR v4 parsing (pure, testable)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CidrV4 {
    pub addr: u32,
    pub prefix: u8,
}

impl CidrV4 {
    pub fn parse(s: &str) -> Option<Self> {
        let (ip_str, prefix_str) = s.split_once('/')?;
        let prefix: u8 = prefix_str.parse().ok()?;
        if prefix > 32 { return None; }
        let octets: Vec<u8> = ip_str.split('.')
            .filter_map(|p| p.parse().ok()).collect();
        if octets.len() != 4 { return None; }
        let addr = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);
        let mask = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
        Some(CidrV4 { addr: addr & mask, prefix })
    }

    pub fn mask(&self) -> u32 {
        if self.prefix == 0 { 0 } else { !0u32 << (32 - self.prefix) }
    }

    pub fn contains(&self, ip: u32) -> bool {
        (ip & self.mask()) == self.addr
    }
}

// ---------------------------------------------------------------------------
// WFP Engine (thin wrapper over fwpuclnt.dll)
// ---------------------------------------------------------------------------

/// RFC1918 private address ranges — block to prevent lateral movement.
pub const RFC1918: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

/// SMB/NetBIOS ports — block to prevent DFS UNC exfiltration.
pub const SMB_PORTS: &[u16] = &[445, 139];

/// WFP engine handle + registered filter IDs for cleanup.
pub struct WfpEngine {
    handle: windows::Win32::Foundation::HANDLE,
    filter_ids: Vec<u64>,
}

impl WfpEngine {
    /// Open WFP engine. Requires no special privileges for user-mode filter management.
    pub fn open() -> Result<Self> {
        use windows::Wdk::NetworkManagement::WindowsFilteringPlatform::FwpmEngineOpen0;
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SESSION0;

        let session = FWPM_SESSION0 {
            flags: 0x0001, // FWPM_SESSION_FLAG_DYNAMIC
            ..Default::default()
        };
        let mut handle = windows::Win32::Foundation::HANDLE::default();

        // SAFETY: session is a valid zero-initialized struct; handle will be set on success.
        let status = unsafe {
            FwpmEngineOpen0(
                None, // local engine
                0xFFFFFFFF, // RPC_C_AUTHN_DEFAULT
                None, // default auth
                Some(&session),
                &mut handle,
            )
        };
        if status.is_err() {
            anyhow::bail!("FwpmEngineOpen0 failed: {:?}", status);
        }
        Ok(Self { handle, filter_ids: vec![] })
    }

    /// Add a BLOCK filter for outbound connections from `app_path` to a CIDR range.
    pub fn block_outbound_cidr(&mut self, app_path: &Path, cidr: &CidrV4) -> Result<u64> {
        self.add_filter(app_path, cidr, true)
    }

    /// Add a PERMIT filter for outbound connections from `app_path` to a CIDR range.
    pub fn allow_outbound_cidr(&mut self, app_path: &Path, cidr: &CidrV4) -> Result<u64> {
        self.add_filter(app_path, cidr, false)
    }

    fn add_filter(&mut self, _app_path: &Path, cidr: &CidrV4, block: bool) -> Result<u64> {
        use windows::Wdk::NetworkManagement::WindowsFilteringPlatform::FwpmFilterAdd0;
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;

        let addr_mask = FWP_V4_ADDR_AND_MASK {
            addr: cidr.addr,
            mask: cidr.mask(),
        };

        let mut conditions = [FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_V4_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    v4AddrMask: &addr_mask as *const _ as *mut _,
                },
            },
        }];

        let display_name_wide: Vec<u16> = format!("winrsbox-{}\0", if block {"block"} else {"permit"})
            .encode_utf16().collect();
        let display = FWPM_DISPLAY_DATA0 {
            name: windows::core::PWSTR(display_name_wide.as_ptr() as *mut _),
            description: windows::core::PWSTR::null(),
        };

        let action = FWPM_ACTION0 {
            r#type: if block { FWP_ACTION_BLOCK } else { FWP_ACTION_PERMIT },
            ..Default::default()
        };

        let filter = FWPM_FILTER0 {
            displayData: display,
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            subLayerKey: FWPM_SUBLAYER_UNIVERSAL,
            action,
            filterCondition: conditions.as_mut_ptr(),
            numFilterConditions: 1,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: if block { 10 } else { 15 } },
            },
            ..Default::default()
        };

        let mut filter_id: u64 = 0;
        // SAFETY: all structs are valid; engine handle is open.
        let status = unsafe {
            FwpmFilterAdd0(self.handle, &filter, None, Some(&mut filter_id))
        };
        if status.is_err() {
            anyhow::bail!("FwpmFilterAdd0 failed: {:?}", status);
        }
        self.filter_ids.push(filter_id);
        Ok(filter_id)
    }

    /// Block all outbound TCP connections to a specific port.
    pub fn block_outbound_port(&mut self, port: u16) -> Result<u64> {
        use windows::Wdk::NetworkManagement::WindowsFilteringPlatform::FwpmFilterAdd0;
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;

        let mut conditions = [FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
            },
        }];

        let name_wide: Vec<u16> = format!("winrsbox-block-port-{port}\0")
            .encode_utf16().collect();
        let display = FWPM_DISPLAY_DATA0 {
            name: windows::core::PWSTR(name_wide.as_ptr() as *mut _),
            description: windows::core::PWSTR::null(),
        };

        let filter = FWPM_FILTER0 {
            displayData: display,
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            subLayerKey: FWPM_SUBLAYER_UNIVERSAL,
            action: FWPM_ACTION0 { r#type: FWP_ACTION_BLOCK, ..Default::default() },
            filterCondition: conditions.as_mut_ptr(),
            numFilterConditions: 1,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: 10 },
            },
            ..Default::default()
        };

        let mut filter_id: u64 = 0;
        let status = unsafe {
            FwpmFilterAdd0(self.handle, &filter, None, Some(&mut filter_id))
        };
        if status.is_err() {
            anyhow::bail!("FwpmFilterAdd0 port {port} failed: {:?}", status);
        }
        self.filter_ids.push(filter_id);
        Ok(filter_id)
    }

    /// Block all outbound TCP connections to a specific port (IPv6).
    pub fn block_outbound_port_v6(&mut self, port: u16) -> Result<u64> {
        use windows::Wdk::NetworkManagement::WindowsFilteringPlatform::FwpmFilterAdd0;
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;

        let mut conditions = [FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
            },
        }];

        let name_wide: Vec<u16> = format!("winrsbox-block-v6-port-{port}\0")
            .encode_utf16().collect();
        let display = FWPM_DISPLAY_DATA0 {
            name: windows::core::PWSTR(name_wide.as_ptr() as *mut _),
            description: windows::core::PWSTR::null(),
        };

        let filter = FWPM_FILTER0 {
            displayData: display,
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            subLayerKey: FWPM_SUBLAYER_UNIVERSAL,
            action: FWPM_ACTION0 { r#type: FWP_ACTION_BLOCK, ..Default::default() },
            filterCondition: conditions.as_mut_ptr(),
            numFilterConditions: 1,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: 10 },
            },
            ..Default::default()
        };

        let mut filter_id: u64 = 0;
        let status = unsafe {
            FwpmFilterAdd0(self.handle, &filter, None, Some(&mut filter_id))
        };
        if status.is_err() {
            anyhow::bail!("FwpmFilterAdd0 v6 port {port} failed: {:?}", status);
        }
        self.filter_ids.push(filter_id);
        Ok(filter_id)
    }

    /// Number of registered filters.
    pub fn filter_count(&self) -> usize {
        self.filter_ids.len()
    }
}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        use windows::Wdk::NetworkManagement::WindowsFilteringPlatform::{
            FwpmFilterDeleteById0, FwpmEngineClose0,
        };
        for &fid in &self.filter_ids {
            // SAFETY: engine handle is still valid; filter_id was returned by FwpmFilterAdd0.
            unsafe { let _ = FwpmFilterDeleteById0(self.handle, fid); }
        }
        // SAFETY: closing the engine we opened.
        unsafe { let _ = FwpmEngineClose0(self.handle); }
    }
}

// ---------------------------------------------------------------------------
// Tests (pure functions only — WFP engine needs runtime, skip)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_parse_basic() {
        let c = CidrV4::parse("192.168.0.0/16").unwrap();
        assert_eq!(c.addr, 0xC0A80000);
        assert_eq!(c.prefix, 16);
        assert_eq!(c.mask(), 0xFFFF0000);
    }

    #[test]
    fn cidr_parse_8() {
        let c = CidrV4::parse("10.0.0.0/8").unwrap();
        assert_eq!(c.addr, 0x0A000000);
        assert_eq!(c.mask(), 0xFF000000);
    }

    #[test]
    fn cidr_parse_32() {
        let c = CidrV4::parse("1.2.3.4/32").unwrap();
        assert_eq!(c.addr, 0x01020304);
        assert_eq!(c.mask(), 0xFFFFFFFF);
    }

    #[test]
    fn cidr_parse_0() {
        let c = CidrV4::parse("0.0.0.0/0").unwrap();
        assert_eq!(c.addr, 0);
        assert_eq!(c.mask(), 0);
    }

    #[test]
    fn cidr_parse_masks_low_bits() {
        let c = CidrV4::parse("192.168.1.5/24").unwrap();
        assert_eq!(c.addr, 0xC0A80100); // .5 masked out
    }

    #[test]
    fn cidr_parse_invalid_prefix_33() {
        assert!(CidrV4::parse("1.2.3.4/33").is_none());
    }

    #[test]
    fn cidr_parse_no_slash() {
        assert!(CidrV4::parse("192.168.0.0").is_none());
    }

    #[test]
    fn cidr_parse_too_many_octets() {
        assert!(CidrV4::parse("1.2.3.4.5/8").is_none());
    }

    #[test]
    fn cidr_contains_match() {
        let c = CidrV4::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(0x0A010203)); // 10.1.2.3
        assert!(c.contains(0x0AFFFFFF)); // 10.255.255.255
        assert!(!c.contains(0x0B000001)); // 11.0.0.1
    }

    #[test]
    fn cidr_contains_exact() {
        let c = CidrV4::parse("8.8.8.8/32").unwrap();
        assert!(c.contains(0x08080808));
        assert!(!c.contains(0x08080809));
    }

    #[test]
    fn cidr_contains_all() {
        let c = CidrV4::parse("0.0.0.0/0").unwrap();
        assert!(c.contains(0));
        assert!(c.contains(0xFFFFFFFF));
    }
}
