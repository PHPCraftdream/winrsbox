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
// Tests (pure functions only — WFP engine needs runtime, skip)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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

    #[test]
    fn cidr_v6_parse_basic() {
        let c = CidrV6::parse("fc00::/7").unwrap();
        assert_eq!(c.prefix, 7);
        assert_eq!(c.addr[0], 0xfc);
        assert_eq!(c.addr[1], 0x00);
    }

    #[test]
    fn cidr_v6_parse_loopback() {
        let c = CidrV6::parse("::1/128").unwrap();
        assert_eq!(c.prefix, 128);
        assert_eq!(c.addr[15], 1);
        assert_eq!(c.addr[0], 0);
    }

    #[test]
    fn cidr_v6_parse_link_local() {
        let c = CidrV6::parse("fe80::/10").unwrap();
        assert_eq!(c.prefix, 10);
        assert_eq!(c.addr[0], 0xfe);
        assert_eq!(c.addr[1], 0x80);
    }

    #[test]
    fn cidr_v6_mask_bytes() {
        let m = CidrV6::mask_bytes(10);
        assert_eq!(m[0], 0xFF);
        assert_eq!(m[1], 0xC0); // 1100_0000
        assert_eq!(m[2], 0x00);
    }

    #[test]
    fn cidr_v6_parse_invalid_prefix() {
        assert!(CidrV6::parse("::1/129").is_none());
    }

    // ----- audit Medium "WFP": APP_ID scoping + loud non-elevated failure -----

    fn unique_temp_file(name: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(name);
        std::fs::write(&p, b"").unwrap();
        (dir, p)
    }

    #[test]
    fn app_id_blob_is_nt_path_of_image() {
        let (_dir, p) = unique_temp_file("wfp_probe_image.exe");
        let blob = app_id_from_path(&p).unwrap();
        assert!(!blob.is_empty());
        // The WFP app id blob is the NT path as UTF-16 wide chars,
        // NUL-terminated (the producer includes the terminator).
        assert_eq!(blob.len() % 2, 0, "wide-char blob must be even-sized");
        let wide: Vec<u16> = blob
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let s = String::from_utf16(&wide)
            .unwrap()
            .trim_end_matches('\0')
            .to_lowercase();
        assert!(s.starts_with('\\'), "app id must be an NT device path, got: {s}");
        assert!(s.ends_with("wfp_probe_image.exe"), "got: {s}");
    }

    #[test]
    fn app_id_blob_rejects_missing_file() {
        // The image path must be verifiable BEFORE any filter is installed --
        // an unverifiable path must never degrade into machine-wide filters.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("does_not_exist.exe");
        let err = app_id_from_path(&p).unwrap_err().to_string();
        assert!(
            err.contains("canonicalize"),
            "must fail before touching the engine, got: {err}"
        );
    }

    #[test]
    fn strip_verbatim_prefix_local_unc_and_plain() {
        assert_eq!(
            strip_verbatim_prefix(Path::new(r"\\?\C:\x\y.exe")),
            PathBuf::from(r"C:\x\y.exe")
        );
        assert_eq!(
            strip_verbatim_prefix(Path::new(r"\\?\UNC\srv\share\x.exe")),
            PathBuf::from(r"\\srv\share\x.exe")
        );
        assert_eq!(
            strip_verbatim_prefix(Path::new(r"C:\already\plain.exe")),
            PathBuf::from(r"C:\already\plain.exe")
        );
    }

    /// The loud-failure contract for a refused filter add: the message must
    /// name the lost guarantee ("NOT ENFORCED") so an operator grepping the
    /// log finds it, and must carry the OS status text. Deliberately does NOT
    /// guess the cause -- unelevation was the historical suspect, but
    /// unelevated dynamic-session adds are observed to succeed on Win10 19045.
    #[test]
    fn probe_failure_message_names_lost_guarantee() {
        let msg = probe_failure_message("WIN32_ERROR(5)");
        assert!(msg.contains("NOT ENFORCED"), "got: {msg}");
        assert!(msg.contains("WIN32_ERROR(5)"), "must carry the status, got: {msg}");
    }

    /// Live smoke test: the engine accepts the canary add and it is deleted
    /// again (dynamic-session objects also die with the session regardless).
    /// Requires the Base Filtering Engine service; where it is stopped this
    /// test fails with the containment-lost error -- exactly the condition
    /// the canary exists to surface.
    #[test]
    fn open_smoke_engine_accepts_probe_and_cleans_up() {
        let engine = WfpEngine::open()
            .expect("WfpEngine::open failed -- is the Base Filtering Engine service running?");
        assert_eq!(engine.filter_count(), 0);
    }

    /// Audit Medium "WFP" fix verification, live path: the engine must accept
    /// an APP_ID-scoped CIDR filter. FwpmFilterAdd0 validates every condition
    /// against the layer schema, so a structurally wrong APP_ID condition
    /// (wrong GUID, wrong value type, dangling blob) is rejected here instead
    /// of silently installed. Engine-side enumeration to re-read the stored
    /// conditions was attempted and is NOT possible for this token
    /// (FwpmFilterCreateEnumHandle0 -> ERROR_ACCESS_DENIED with a UAC-filtered
    /// admin token; FwpmFilterAdd0 leaves its out-param id at 0 in a dynamic
    /// session, so FwpmFilterGetById0 has nothing to look up).
    #[test]
    fn add_filter_installs_app_id_and_cidr_conditions_live() {
        let (_dir, image) = unique_temp_file("wfp_live_image.exe");
        let cidr = CidrV4::parse("127.0.0.0/8").unwrap();
        let mut engine = WfpEngine::open()
            .expect("WfpEngine::open failed -- is the Base Filtering Engine service running?");
        engine
            .block_outbound_cidr(&image, &cidr)
            .expect("APP_ID-scoped block filter rejected by the engine");
        assert_eq!(engine.filter_count(), 1);
        // Dynamic-session objects die with the engine session, so dropping
        // here is the cleanup path; nothing persists beyond this process.
        drop(engine);
    }

    /// Every containment filter must be bound to the sandboxed image.
    ///
    /// `block_outbound_cidr_v6`, `block_outbound_port` and
    /// `block_outbound_port_v6` were each built with a single condition and no
    /// `FWPM_CONDITION_ALE_APP_ID`, so they matched EVERY process on the
    /// machine: while any sandbox ran, the whole host lost SMB egress on
    /// 445/139 and connectivity to the private IPv6 ranges. A sandbox must
    /// not reconfigure the operator's network.
    ///
    /// Source-level because building a filter needs a live WFP engine and
    /// elevation-dependent state; the property to protect is structural — a
    /// new `block_outbound_*` helper added without an `app_path` parameter is
    /// the regression, and it is visible in the signature.
    #[test]
    fn every_block_filter_is_scoped_to_an_app_path() {
        let src = include_str!("wfp.rs");
        let mut unscoped: Vec<&str> = Vec::new();
        for line in src.lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix("pub fn block_outbound_") else { continue };
            // `app_path: &Path` is what carries the APP_ID condition.
            if !rest.contains("app_path: &Path") {
                unscoped.push(line);
            }
        }
        assert!(
            unscoped.is_empty(),
            "these filter helpers take no app_path, so they would match every              process on the machine: {unscoped:#?}",
        );
    }
}
