// WFP (Windows Filtering Platform) user-mode network filtering.
//
// Kernel-enforced — direct syscalls cannot bypass.
// Registers filters via fwpuclnt.dll from user-mode.
//
// Every v4 CIDR filter is scoped to the sandboxed image via an
// FWPM_CONDITION_ALE_APP_ID condition (exact match on the image's NT device
// path); without it a filter matches every process on the machine. Installing
// open() verifies with a canary add+delete that the engine actually accepts
// filters before the caller relies on it, and fails loudly if it does not.
// Observed on Windows 10 19045 with a UAC-filtered token: unelevated
// dynamic-session filter adds DO succeed, so unelevation alone is not a
// containment loss -- but any engine that refuses the canary means NO
// kernel-level network containment, and the launcher says so in those words.

use anyhow::Result;
use std::path::{Path, PathBuf};

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
// CIDR v6 parsing (pure, testable)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrV6 {
    pub addr: [u8; 16],
    pub prefix: u8,
}

impl CidrV6 {
    pub fn parse(s: &str) -> Option<Self> {
        let (ip_str, prefix_str) = s.split_once('/')?;
        let prefix: u8 = prefix_str.parse().ok()?;
        if prefix > 128 { return None; }

        let ip: std::net::Ipv6Addr = ip_str.parse().ok()?;
        let mut addr = ip.octets();
        let mask = Self::mask_bytes(prefix);
        for i in 0..16 {
            addr[i] &= mask[i];
        }
        Some(CidrV6 { addr, prefix })
    }

    pub fn mask_bytes(prefix: u8) -> [u8; 16] {
        let mut mask = [0u8; 16];
        let full_bytes = (prefix / 8) as usize;
        let remaining_bits = prefix % 8;
        for byte in mask.iter_mut().take(full_bytes) {
            *byte = 0xFF;
        }
        if full_bytes < 16 && remaining_bits > 0 {
            mask[full_bytes] = !0u8 << (8 - remaining_bits);
        }
        mask
    }
}

// ---------------------------------------------------------------------------
// WFP Engine (thin wrapper over fwpuclnt.dll)
// ---------------------------------------------------------------------------

/// RFC1918 private address ranges — block to prevent lateral movement.
pub const RFC1918: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

/// IPv6 private/local ranges — block to prevent lateral movement over v6.
pub const IPV6_PRIVATE: &[&str] = &["fc00::/7", "fe80::/10", "::1/128"];

/// SMB/NetBIOS ports — block to prevent DFS UNC exfiltration.
pub const SMB_PORTS: &[u16] = &[445, 139];

// ---------------------------------------------------------------------------
// APP_ID binding (helpers testable without a WFP engine)
// ---------------------------------------------------------------------------

/// Map a Win32 image path to the WFP application identifier blob: the exact
/// NT device path (`\device\harddiskvolumeN\...`) the kernel records for a
/// process image. APP_ID matching is an exact byte comparison, so the path
/// must be canonical; a path we cannot canonicalize must fail loudly rather
/// than install filters that silently match nothing (or fall back to
/// machine-wide filters).
fn app_id_from_path(app_path: &Path) -> Result<Vec<u8>> {
    use std::ffi::c_void;
    use windows::core::PCWSTR;
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FWP_BYTE_BLOB,
    };

    let canonical = std::fs::canonicalize(app_path).map_err(|e| {
        anyhow::anyhow!(
            "cannot canonicalize sandboxed image path {}: {e} -- refusing to install \
             APP_ID-scoped WFP filters against an unverifiable path",
            app_path.display()
        )
    })?;
    let dos = strip_verbatim_prefix(&canonical);
    let mut wide: Vec<u16> = dos.as_os_str().to_string_lossy().encode_utf16().collect();
    wide.push(0);

    let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated and outlives the call; `blob` is the
    // out-parameter. On success the API allocates the blob, freed below.
    let status = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(wide.as_ptr()), &mut blob) };
    if status != 0 {
        anyhow::bail!(
            "FwpmGetAppIdFromFileName0 failed for {}: 0x{status:08X}",
            dos.display()
        );
    }
    if blob.is_null() {
        anyhow::bail!("FwpmGetAppIdFromFileName0 returned no app id for {}", dos.display());
    }
    // SAFETY: `blob` came from a successful FwpmGetAppIdFromFileName0, so
    // size/data describe an allocated buffer. Copy the bytes, then free the
    // blob via FwpmFreeMemory0 as the API requires (FwpmFilterAdd0 copies the
    // condition value, so the blob does not need to outlive this function).
    let app_id = unsafe {
        let (size, data) = {
            let b = &*blob;
            (b.size, b.data)
        };
        let out = if size == 0 || data.is_null() {
            None
        } else {
            Some(std::slice::from_raw_parts(data, size as usize).to_vec())
        };
        FwpmFreeMemory0(std::ptr::addr_of_mut!(blob).cast::<*mut c_void>());
        match out {
            Some(v) => v,
            None => anyhow::bail!(
                "FwpmGetAppIdFromFileName0 returned an empty app id for {}",
                dos.display()
            ),
        }
    };
    Ok(app_id)
}

/// `\\?\C:\a\b` becomes `C:\a\b`; `\\?\UNC\srv\share` becomes `\\srv\share`.
/// The Rtl path conversion behind FwpmGetAppIdFromFileName0 accepts both
/// forms, but the plain form is the battle-tested input, and canonicalize()
/// always returns the verbatim form.
fn strip_verbatim_prefix(p: &Path) -> PathBuf {
    let s = p.as_os_str().to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{}", rest));
    }
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        return PathBuf::from(rest.to_string());
    }
    p.to_path_buf()
}

/// The one loud message the launcher prints when the WFP engine cannot
/// install filters. Deliberately does NOT guess the cause (unelevation was
/// the historical suspect; unelevated dynamic-session adds are observed to
/// succeed on Win10 19045).
fn probe_failure_message(status_text: &str) -> String {
    format!(
        "NETWORK CONTAINMENT NOT ENFORCED: the WFP engine refused a test filter ({status_text}) -- kernel-level outbound filtering will NOT be installed this run. Check that the Base Filtering Engine service is running and that filter management is permitted for this account."
    )
}

/// WFP engine handle + registered filter IDs for cleanup.
pub struct WfpEngine {
    handle: windows::Win32::Foundation::HANDLE,
    filter_ids: Vec<u64>,
}

impl WfpEngine {
    /// Open the WFP engine and verify it actually accepts filters.
    ///
    /// Fails loudly when filters cannot be installed (Base Filtering Engine
    /// unavailable, filter-add access denied, ...). Callers must treat `Err`
    /// as "network containment NOT ENFORCED", not as an optional nicety:
    /// continuing silently is the failure mode this check exists to prevent.
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
        let engine = Self { handle, filter_ids: vec![] };
        // A session can open while every filter add is denied (broken BFE,
        // policy-restricted token, ...) -- historically the silent "no
        // containment" path. Probe before handing the engine back; on failure the
        // engine's Drop closes the session (dynamic sessions hold no
        // persistent objects).
        engine.probe_write_access()?;
        Ok(engine)
    }

    /// Verify the engine accepts filters before the caller relies on it.
    ///
    /// The probe filter's conditions can never match real traffic (reserved
    /// class-E destination 240.0.0.0/32, plain PERMIT without
    /// CLEAR_ACTION_RIGHT, sub-millisecond lifetime before deletion), so the
    /// probe cannot open a containment hole of its own.
    fn probe_write_access(&self) -> Result<()> {
        use windows::Wdk::NetworkManagement::WindowsFilteringPlatform::{
            FwpmFilterAdd0, FwpmFilterDeleteById0,
        };
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;

        let addr_mask = FWP_V4_ADDR_AND_MASK {
            addr: 0xF000_0000, // 240.0.0.0 -- reserved class E
            mask: 0xFFFFFFFF,
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
        let name_wide: Vec<u16> = "winrsbox-write-probe\0".encode_utf16().collect();
        let filter = FWPM_FILTER0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(name_wide.as_ptr() as *mut _),
                description: windows::core::PWSTR::null(),
            },
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            subLayerKey: FWPM_SUBLAYER_UNIVERSAL,
            action: FWPM_ACTION0 { r#type: FWP_ACTION_PERMIT, ..Default::default() },
            flags: FWPM_FILTER_FLAG_NONE,
            filterCondition: conditions.as_mut_ptr(),
            numFilterConditions: 1,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: 15 },
            },
            ..Default::default()
        };
        let mut probe_id: u64 = 0;
        // SAFETY: structs valid; engine handle open; probe_id is the out-param.
        let status = unsafe { FwpmFilterAdd0(self.handle, &filter, None, Some(&mut probe_id)) };
        if status.is_err() {
            anyhow::bail!("{}", probe_failure_message(&format!("{status:?}")));
        }
        // SAFETY: probe_id was returned by the successful add above.
        unsafe { let _ = FwpmFilterDeleteById0(self.handle, probe_id); }
        Ok(())
    }

    /// Add a BLOCK filter for outbound connections from `app_path` to a CIDR range.
    pub fn block_outbound_cidr(&mut self, app_path: &Path, cidr: &CidrV4) -> Result<u64> {
        self.add_filter(app_path, cidr, true)
    }

    /// Add a PERMIT filter for outbound connections from `app_path` to a CIDR range.
    pub fn allow_outbound_cidr(&mut self, app_path: &Path, cidr: &CidrV4) -> Result<u64> {
        self.add_filter(app_path, cidr, false)
    }

    fn add_filter(&mut self, app_path: &Path, cidr: &CidrV4, block: bool) -> Result<u64> {
        use windows::Wdk::NetworkManagement::WindowsFilteringPlatform::FwpmFilterAdd0;
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;

        // Bind the filter to the sandboxed image BEFORE anything else: without
        // the APP_ID condition the filter would match every process on the
        // machine, so an unusable app id must abort the add -- never fall back
        // to an unscoped filter.
        let mut app_id = app_id_from_path(app_path)?;
        let mut app_blob = FWP_BYTE_BLOB {
            size: app_id.len() as u32,
            data: app_id.as_mut_ptr(),
        };

        let addr_mask = FWP_V4_ADDR_AND_MASK {
            addr: cidr.addr,
            mask: cidr.mask(),
        };

        let mut conditions = [
            FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        byteBlob: &mut app_blob,
                    },
                },
            },
            FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_V4_ADDR_MASK,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        v4AddrMask: &addr_mask as *const _ as *mut _,
                    },
                },
            },
        ];

        let display_name_wide: Vec<u16> = format!("winrsbox-{}\0", if block {"block"} else {"permit"})
            .encode_utf16().collect();
        let desc_wide: Vec<u16> = format!("{}\0", app_path.display())
            .encode_utf16().collect();
        let display = FWPM_DISPLAY_DATA0 {
            name: windows::core::PWSTR(display_name_wide.as_ptr() as *mut _),
            description: windows::core::PWSTR(desc_wide.as_ptr() as *mut _),
        };

        let action = FWPM_ACTION0 {
            r#type: if block { FWP_ACTION_BLOCK } else { FWP_ACTION_PERMIT },
            ..Default::default()
        };

        // Hard block: CLEAR_ACTION_RIGHT makes a BLOCK terminating so no
        // higher-weight PERMIT (ours or any third-party filter sharing the
        // universal sublayer) can override it. Without it, a PERMIT with a
        // larger weight in the same sublayer wins → containment hole.
        let filter = FWPM_FILTER0 {
            displayData: display,
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            subLayerKey: FWPM_SUBLAYER_UNIVERSAL,
            action,
            flags: if block {
                FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
            } else {
                FWPM_FILTER_FLAG_NONE
            },
            filterCondition: conditions.as_mut_ptr(),
            numFilterConditions: 2,
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

    /// Add a BLOCK filter for outbound IPv6 connections from `app_path` to a
    /// CIDR range.
    ///
    /// `app_path` is not optional. Without the `ALE_APP_ID` condition this
    /// filter matched EVERY process on the machine, so for as long as any
    /// sandbox was running the whole host lost connectivity to the private
    /// IPv6 ranges — a sandbox silently reconfiguring the operator's network.
    /// The v4 twin has always been scoped; this one was not.
    pub fn block_outbound_cidr_v6(&mut self, app_path: &Path, cidr: &CidrV6) -> Result<u64> {
        use windows::Wdk::NetworkManagement::WindowsFilteringPlatform::FwpmFilterAdd0;
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;

        // Same contract as `add_filter`: an unusable app id aborts the add.
        // Never fall back to an unscoped filter.
        let mut app_id = app_id_from_path(app_path)?;
        let mut app_blob = FWP_BYTE_BLOB {
            size: app_id.len() as u32,
            data: app_id.as_mut_ptr(),
        };

        let addr_mask = FWP_V6_ADDR_AND_MASK {
            addr: cidr.addr,
            prefixLength: cidr.prefix,
        };

        let mut conditions = [
            FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        byteBlob: &mut app_blob,
                    },
                },
            },
            FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_V6_ADDR_MASK,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        v6AddrMask: &addr_mask as *const _ as *mut _,
                    },
                },
            },
        ];

        let name_wide: Vec<u16> = format!("winrsbox-block-v6-cidr\0")
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
            flags: FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
            filterCondition: conditions.as_mut_ptr(),
            numFilterConditions: conditions.len() as u32,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: 10 },
            },
            ..Default::default()
        };

        let mut filter_id: u64 = 0;
        // SAFETY: all structs valid; engine handle is open.
        let status = unsafe {
            FwpmFilterAdd0(self.handle, &filter, None, Some(&mut filter_id))
        };
        if status.is_err() {
            anyhow::bail!("FwpmFilterAdd0 v6 cidr failed: {:?}", status);
        }
        self.filter_ids.push(filter_id);
        Ok(filter_id)
    }

    /// Block all outbound TCP connections to a specific port.
    pub fn block_outbound_port(&mut self, app_path: &Path, port: u16) -> Result<u64> {
        use windows::Wdk::NetworkManagement::WindowsFilteringPlatform::FwpmFilterAdd0;
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;

        // Same contract as `add_filter`: an unusable app id aborts the add.
        // Never fall back to an unscoped filter.
        let mut app_id = app_id_from_path(app_path)?;
        let mut app_blob = FWP_BYTE_BLOB {
            size: app_id.len() as u32,
            data: app_id.as_mut_ptr(),
        };

        let mut conditions = [
            FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        byteBlob: &mut app_blob,
                    },
                },
            },
            FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
                },
            },
        ];

        let name_wide: Vec<u16> = format!("winrsbox-block-port-{port}\0")
            .encode_utf16().collect();
        let display = FWPM_DISPLAY_DATA0 {
            name: windows::core::PWSTR(name_wide.as_ptr() as *mut _),
            description: windows::core::PWSTR::null(),
        };

        // Hard block (CLEAR_ACTION_RIGHT) so a higher-weight PERMIT cannot
        // override the SMB egress block in the shared universal sublayer.
        let filter = FWPM_FILTER0 {
            displayData: display,
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            subLayerKey: FWPM_SUBLAYER_UNIVERSAL,
            action: FWPM_ACTION0 { r#type: FWP_ACTION_BLOCK, ..Default::default() },
            flags: FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
            filterCondition: conditions.as_mut_ptr(),
            numFilterConditions: conditions.len() as u32,
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
    pub fn block_outbound_port_v6(&mut self, app_path: &Path, port: u16) -> Result<u64> {
        use windows::Wdk::NetworkManagement::WindowsFilteringPlatform::FwpmFilterAdd0;
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;

        // Same contract as `add_filter`: an unusable app id aborts the add.
        // Never fall back to an unscoped filter.
        let mut app_id = app_id_from_path(app_path)?;
        let mut app_blob = FWP_BYTE_BLOB {
            size: app_id.len() as u32,
            data: app_id.as_mut_ptr(),
        };

        let mut conditions = [
            FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        byteBlob: &mut app_blob,
                    },
                },
            },
            FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
                },
            },
        ];

        let name_wide: Vec<u16> = format!("winrsbox-block-v6-port-{port}\0")
            .encode_utf16().collect();
        let display = FWPM_DISPLAY_DATA0 {
            name: windows::core::PWSTR(name_wide.as_ptr() as *mut _),
            description: windows::core::PWSTR::null(),
        };

        // Hard block (CLEAR_ACTION_RIGHT) so a higher-weight PERMIT cannot
        // override the SMB egress block in the shared universal sublayer.
        let filter = FWPM_FILTER0 {
            displayData: display,
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            subLayerKey: FWPM_SUBLAYER_UNIVERSAL,
            action: FWPM_ACTION0 { r#type: FWP_ACTION_BLOCK, ..Default::default() },
            flags: FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
            filterCondition: conditions.as_mut_ptr(),
            numFilterConditions: conditions.len() as u32,
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
// Install entry point (fail-closed)
// ---------------------------------------------------------------------------

/// Outcome of `install_outbound_filters`.
pub enum WfpInstall {
    /// Guarded network was not requested — no filters installed; launch may proceed.
    NotRequested,
    /// Guarded network requested and every filter installed. The caller must
    /// keep the engine alive for the run; dropping it removes the filters.
    Installed(WfpEngine),
    /// Guarded network was requested but the kernel-level guarantee could not
    /// be established. The caller must fail closed (refuse the launch).
    Refused(String),
}

/// WFP kernel-level network filtering (needs fwpuclnt.dll).
///
/// Every filter is scoped by `FWPM_CONDITION_ALE_APP_ID`, an exact match on
/// the image the kernel records for a process. A `.bat`/`.cmd` target has
/// no such image: kernel32 rewrites it to `%COMSPEC% /c <script>`, so the
/// root process is cmd.exe and the script is merely an argument. An app id
/// built from the script path would therefore match no process at all —
/// filters would install successfully and silently do nothing. (Scoping to
/// cmd.exe instead would be worse: it would look like coverage while the
/// program that actually opens sockets runs as its child, which APP_ID
/// scoping never reaches either way.)
///
/// Fail-closed: when guarded network is requested (`net_guarded &&
/// guard_enabled`) the caller must get the kernel layer the security policy
/// promises or not launch at all. Every failure — engine unavailable,
/// `.bat`/`.cmd` target, any single filter add — comes back as
/// [`WfpInstall::Refused`], and the install is all-or-nothing: on a failed
/// add the engine is dropped and its `Drop` deletes every filter registered
/// so far, so a partial filter set never persists.
pub fn install_outbound_filters(
    net_guarded: bool,
    guard_enabled: bool,
    block_localhost: bool,
    target: &Path,
) -> WfpInstall {
    let target_is_script = target
        .extension()
        .map(|e| {
            let e = e.to_string_lossy().to_ascii_lowercase();
            e == "bat" || e == "cmd"
        })
        .unwrap_or(false);
    // `net_guarded` first: with network containment off the engine is never
    // opened, so not one `winrsbox-block-*` filter is registered and the
    // sandbox leaves no trace in the system's network configuration.
    if !(net_guarded && guard_enabled) {
        return WfpInstall::NotRequested;
    }
    if target_is_script {
        return WfpInstall::Refused(format!(
            "a .bat/.cmd target ('{}') has no image of its own — kernel32 rewrites it to \
             %COMSPEC% /c <script>, so the root process is cmd.exe and the script is merely \
             an argument; an APP_ID built from the script path would match no process at all, \
             so the promised kernel-level network layer cannot exist — refusing the launch \
             rather than running unprotected",
            target.display(),
        ));
    }
    let mut engine = match WfpEngine::open() {
        Ok(engine) => engine,
        Err(e) => return WfpInstall::Refused(format!("WFP engine unavailable: {e}")),
    };
    match add_all_filters(&mut engine, target, block_localhost) {
        Ok(()) => {
            let fc = engine.filter_count();
            if crate::observe::jsonl_log::console_verbose() {
                println!("[sandbox] WFP: {fc} outbound filters registered");
            }
            crate::observe::jsonl_log::log(crate::observe::jsonl_log::Event::wfp(fc));
            WfpInstall::Installed(engine)
        }
        Err(e) => {
            // All-or-nothing: Drop deletes every filter registered before the
            // failure, so a partial filter set never persists.
            drop(engine);
            WfpInstall::Refused(format!("WFP filter installation incomplete: {e}"))
        }
    }
}

/// Add every containment filter the guarded network promises: RFC1918,
/// private IPv6, optional localhost, SMB/NetBIOS egress. Every failure
/// propagates — the caller drops the engine on `Err`, which deletes the
/// filters already added, so a run never continues on a partial set.
fn add_all_filters(engine: &mut WfpEngine, target: &Path, block_localhost: bool) -> Result<()> {
    // Block lateral movement to RFC1918 private ranges
    for cidr_str in RFC1918 {
        let Some(cidr) = CidrV4::parse(cidr_str) else {
            anyhow::bail!("cannot parse hardcoded CIDR {cidr_str}");
        };
        engine.block_outbound_cidr(target, &cidr)?;
    }
    // Block lateral movement to IPv6 private/local ranges
    for cidr_str in IPV6_PRIVATE {
        let Some(cidr) = CidrV6::parse(cidr_str) else {
            anyhow::bail!("cannot parse hardcoded CIDR {cidr_str}");
        };
        engine.block_outbound_cidr_v6(target, &cidr)?;
    }
    // Block localhost connections (opt-in — breaks MCP/LSP).
    if block_localhost {
        let Some(lo) = CidrV4::parse("127.0.0.0/8") else {
            anyhow::bail!("cannot parse hardcoded CIDR 127.0.0.0/8");
        };
        engine.block_outbound_cidr(target, &lo)?;
    }
    // Block SMB/NetBIOS egress (IPv4 + IPv6) — prevents DFS UNC
    // exfiltration to remote servers.
    for port in SMB_PORTS {
        engine.block_outbound_port(target, *port)?;
        engine.block_outbound_port_v6(target, *port)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;

