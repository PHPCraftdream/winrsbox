// Self-contained owner for a redirected or copied OBJECT_ATTRIBUTES.
//
// Audit H-C2 + M-S2 mitigation. Two related problems addressed by one helper:
//
//   H-C2 — the previous code repeated this triple-init pattern 8x in
//   fs_hooks.rs:
//
//     let nt_buf = make_overlay_nt_buf(&overlay_dos);
//     let mut new_ustr = UNICODE_STRING { Length: ..., Buffer: nt_buf.as_ptr() };
//     let mut new_attrs = OBJECT_ATTRIBUTES { ObjectName: &mut new_ustr, ... };
//
//   The lifetime invariant ("nt_buf must outlive new_ustr, new_attrs") was
//   encoded only by stack-declaration order. One accidental reorder during a
//   refactor = use-after-free into the kernel.
//
//   M-S2 — TOCTOU double-fetch on UNICODE_STRING.Buffer. The kernel re-reads
//   the buffer after our classifier runs. A concurrent thread in the
//   sandboxed process can mutate Buffer's contents between our check and the
//   syscall, redirecting the actual open to a different path. Mitigation:
//   for Passthrough (and any case where we'd hand the original pointer to
//   the kernel) we COPY the UTF-16 buffer into hook-owned memory and pass
//   the copy.
//
// Self-referential safety: ObjectName points at &self.ustr, and ustr.Buffer
// points into self.nt_buf. Vec<u16>'s heap allocation is address-stable
// across struct moves, so ustr.Buffer survives even if HookedAttrs is moved.
// The ObjectName -> &ustr pointer is recomputed in as_ptr_mut() so it
// always reflects self's current address. The struct exists for one
// syscall; the kernel does not retain OBJECT_ATTRIBUTES after the call
// returns.

use ntapi::winapi::shared::ntdef::{
    OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
};

use crate::hooks::make_overlay_nt_buf;

/// Maximum bytes (NOT chars) accepted for the original ObjectName buffer in
/// the TOCTOU passthrough copy. `UNICODE_STRING.Length` is a u16, so the
/// physical maximum is 65534 bytes (=32767 chars + null padding). Anything
/// reported above 65534 bytes is malformed and refused — copying multi-MB
/// hostile input per syscall would be a DoS amplification.
const MAX_PASSTHROUGH_LEN_BYTES: u16 = 65534;

/// Owns the resources that back a substituted `OBJECT_ATTRIBUTES`.
///
/// Constructed via [`HookedAttrs::redirect`] (Cow/Mock overlay rewrite) or
/// [`HookedAttrs::copy_passthrough`] (TOCTOU defense). Use
/// [`HookedAttrs::as_ptr_mut`] to obtain the pointer to hand to the kernel.
///
/// SAFETY invariants:
/// 1. `nt_buf` is the unique owner of the UTF-16 path bytes.
/// 2. `ustr.Buffer` aliases `nt_buf.as_ptr()` for `nt_buf.len()` u16s.
/// 3. `attrs.ObjectName` is set to `&self.ustr` by `as_ptr_mut()` AFTER any
///    move of `self`, so the pointer is always valid for the caller's use.
/// 4. The struct must outlive the kernel call that reads the returned
///    OBJECT_ATTRIBUTES pointer.
pub(crate) struct HookedAttrs {
    /// Null-terminated UTF-16 path data. Heap allocation owned by this struct.
    ///
    /// SAFETY-critical: read via raw pointer (`ustr.Buffer`), so the borrow
    /// checker can't see the read and would flag it as dead. The field MUST
    /// stay alive — dropping it would dangle every pointer derived from it.
    #[allow(dead_code)]
    nt_buf: Vec<u16>,
    /// UNICODE_STRING with Buffer pointing into `nt_buf`. The Length /
    /// MaximumLength fields are computed at construction.
    ustr: UNICODE_STRING,
    /// OBJECT_ATTRIBUTES with ObjectName set by `as_ptr_mut()` (lazy so
    /// moves of `self` don't dangle).
    attrs: OBJECT_ATTRIBUTES,
}

impl HookedAttrs {
    /// Build a `HookedAttrs` that substitutes the path in `orig` with the
    /// overlay/redirect DOS path `dos_path` (NT-formatted via
    /// `make_overlay_nt_buf`). Non-path fields (`RootDirectory`,
    /// `Attributes`, `SecurityDescriptor`) are copied from `orig`. `Attributes`
    /// is OR'd with `OBJ_CASE_INSENSITIVE` to match the prior open-call
    /// behaviour in fs_hooks.rs.
    ///
    /// `force_null_sqos`:
    /// - `true` (Mock paths in NtCreateFile/NtOpenFile): set
    ///   `SecurityQualityOfService = null` because NT file opens reject a
    ///   non-null SQOS on the kernel side (STATUS_INVALID_PARAMETER on some
    ///   build configurations — empirically observed; the comment in the
    ///   previous code in fs_hooks.rs called this out for Mock paths).
    /// - `false` (Cow + Query hooks): copy `orig.SecurityQualityOfService`
    ///   verbatim.
    ///
    /// SAFETY: `orig` must be a valid OBJECT_ATTRIBUTES for the duration of
    /// this call (callers obtain it from the NT hook parameter).
    pub(crate) unsafe fn redirect(
        orig: &OBJECT_ATTRIBUTES,
        dos_path: &str,
        force_null_sqos: bool,
    ) -> Self {
        let nt_buf = make_overlay_nt_buf(dos_path);
        // nt_buf is `\??\<path>\0` (null-terminated). Length excludes the
        // trailing null; MaximumLength includes it.
        let char_count = nt_buf.len().saturating_sub(1);
        let ustr = UNICODE_STRING {
            Length: (char_count * 2) as u16,
            MaximumLength: (nt_buf.len() * 2) as u16,
            Buffer: nt_buf.as_ptr() as *mut u16,
        };
        let sqos = if force_null_sqos {
            std::ptr::null_mut()
        } else {
            orig.SecurityQualityOfService
        };
        let attrs = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            // ObjectName left null here — as_ptr_mut() patches it to
            // &self.ustr right before returning the pointer to the kernel.
            ObjectName: std::ptr::null_mut(),
            Attributes: orig.Attributes | OBJ_CASE_INSENSITIVE,
            SecurityDescriptor: orig.SecurityDescriptor,
            SecurityQualityOfService: sqos,
        };
        HookedAttrs { nt_buf, ustr, attrs }
    }

    /// Build a `HookedAttrs` that COPIES the original ObjectName UTF-16
    /// buffer into hook-owned memory, preserving every other field of
    /// `orig`. Use for the Passthrough path to close the TOCTOU
    /// double-fetch gap on `UNICODE_STRING.Buffer`.
    ///
    /// Returns `None` (signaling the caller to fall back to the original
    /// pointer) when:
    ///   - `orig.ObjectName.is_null()` — no buffer to copy.
    ///   - `orig.ObjectName.Buffer.is_null()` — nothing to read.
    ///   - `orig.ObjectName.Length` is zero — empty name.
    ///   - `orig.ObjectName.Length > MAX_PASSTHROUGH_LEN_BYTES` — DoS
    ///     amplification refusal; the kernel rejects this length too, so
    ///     fall through and let the syscall fail naturally.
    ///
    /// SAFETY: `orig` must be a valid OBJECT_ATTRIBUTES with a readable
    /// (possibly null) ObjectName for the duration of this call. The
    /// returned HookedAttrs (if Some) inherits `orig.RootDirectory`,
    /// `Attributes`, `SecurityDescriptor`, `SecurityQualityOfService`
    /// verbatim — no modification.
    pub(crate) unsafe fn copy_passthrough(orig: &OBJECT_ATTRIBUTES) -> Option<Self> {
        if orig.ObjectName.is_null() {
            return None;
        }
        let src = &*orig.ObjectName;
        if src.Buffer.is_null() || src.Length == 0 {
            return None;
        }
        if src.Length > MAX_PASSTHROUGH_LEN_BYTES {
            return None;
        }
        // Length is in bytes, but Buffer is u16; char count = Length/2.
        let char_count = (src.Length / 2) as usize;
        // SAFETY: src.Buffer is non-null and points to at least src.Length
        // bytes per the NT UNICODE_STRING contract.
        let slice = std::slice::from_raw_parts(src.Buffer, char_count);
        // Copy the buffer into hook-owned heap memory. No null terminator
        // appended — UNICODE_STRING is length-prefixed, not null-terminated,
        // so we mirror what the caller passed exactly.
        let nt_buf: Vec<u16> = slice.to_vec();

        let ustr = UNICODE_STRING {
            Length: src.Length,
            // MaximumLength = Length (no slack — we own a tight copy).
            MaximumLength: src.Length,
            Buffer: nt_buf.as_ptr() as *mut u16,
        };
        let attrs = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: orig.RootDirectory,
            ObjectName: std::ptr::null_mut(),
            Attributes: orig.Attributes,
            SecurityDescriptor: orig.SecurityDescriptor,
            SecurityQualityOfService: orig.SecurityQualityOfService,
        };
        Some(HookedAttrs { nt_buf, ustr, attrs })
    }

    /// Returns the pointer to hand to the kernel. Patches
    /// `attrs.ObjectName` to point at `self.ustr` first, so the returned
    /// pointer is always coherent even if `self` was moved between
    /// construction and this call.
    ///
    /// SAFETY: the returned pointer is only valid while `self` is alive.
    /// The kernel reads it during the syscall; the struct must not be
    /// dropped before the syscall returns.
    pub(crate) fn as_ptr_mut(&mut self) -> *mut OBJECT_ATTRIBUTES {
        // Re-anchor ObjectName -> &mut self.ustr after any move of self.
        self.attrs.ObjectName = &mut self.ustr as *mut UNICODE_STRING;
        &mut self.attrs as *mut OBJECT_ATTRIBUTES
    }
}

// ---------------------------------------------------------------------------
// Unit tests — pure, FFI-free.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a fresh OBJECT_ATTRIBUTES wrapping a caller-supplied
    /// UNICODE_STRING. Used to simulate the "user-memory" input the kernel
    /// would see.
    fn fake_orig(ustr: *mut UNICODE_STRING) -> OBJECT_ATTRIBUTES {
        OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: 0x1234_5678 as *mut _,
            ObjectName: ustr,
            Attributes: 0x42,
            SecurityDescriptor: 0xAAAA_BBBB as *mut _,
            SecurityQualityOfService: 0xCCCC_DDDD as *mut _,
        }
    }

    /// Audit H-C2 — verify the redirect-built UNICODE_STRING.Buffer points
    /// into the owned nt_buf (NOT at some arbitrary address) so the
    /// self-referential invariant holds.
    #[test]
    fn redirect_yields_nt_path_pointing_into_buf() {
        let orig = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: std::ptr::null_mut(),
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let h = unsafe { HookedAttrs::redirect(&orig, r"C:\overlay\x.txt", false) };
        let buf_ptr = h.nt_buf.as_ptr();
        assert_eq!(h.ustr.Buffer as *const u16, buf_ptr);
        // Spot-check the first character is `\` (start of `\??\C:\overlay\...`)
        assert_eq!(unsafe { *h.nt_buf.as_ptr() }, b'\\' as u16);
    }

    /// Audit H-C2 — Length / MaximumLength bytes must align with the
    /// buffer's u16 count (1 char = 2 bytes; null terminator excluded from
    /// Length).
    #[test]
    fn redirect_lengths_consistent() {
        let orig = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: std::ptr::null_mut(),
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let h = unsafe { HookedAttrs::redirect(&orig, r"C:\a.txt", false) };
        // nt_buf is `\??\C:\a.txt\0` = 13 u16 (12 chars + null) = 26 bytes total.
        // Length excludes the trailing null: 12 chars * 2 = 24 bytes.
        // MaximumLength includes it: 13 chars * 2 = 26 bytes.
        let total_chars = h.nt_buf.len();
        assert_eq!(h.ustr.MaximumLength as usize, total_chars * 2);
        assert_eq!(h.ustr.Length as usize, (total_chars - 1) * 2);
        // Sanity: the literal path length we expect.
        assert_eq!(h.ustr.Length, 24);
        assert_eq!(h.ustr.MaximumLength, 26);
    }

    /// Audit H-C2 — force_null_sqos = true must zero the SQOS field
    /// regardless of the orig's value. (Used for Mock paths in
    /// NtCreateFile/NtOpenFile where a non-null SQOS rejects the open.)
    #[test]
    fn redirect_force_null_sqos_zeros_field() {
        let orig = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: std::ptr::null_mut(),
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: 0xDEAD_BEEF as *mut _,
        };
        let h_force = unsafe { HookedAttrs::redirect(&orig, r"C:\a.txt", true) };
        assert!(h_force.attrs.SecurityQualityOfService.is_null());
        let h_keep = unsafe { HookedAttrs::redirect(&orig, r"C:\a.txt", false) };
        assert_eq!(h_keep.attrs.SecurityQualityOfService as usize, 0xDEAD_BEEF);
    }

    /// Audit H-C2 — Attributes must always include OBJ_CASE_INSENSITIVE
    /// because Windows file paths are case-insensitive and the existing
    /// fs_hooks.rs convention OR'd this flag in unconditionally.
    #[test]
    fn redirect_attributes_include_case_insensitive() {
        let orig = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: std::ptr::null_mut(),
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let h = unsafe { HookedAttrs::redirect(&orig, r"C:\a.txt", false) };
        assert!(h.attrs.Attributes & OBJ_CASE_INSENSITIVE != 0);
    }

    /// Audit M-S2 — the whole point of TOCTOU copy. After we build the
    /// HookedAttrs::copy_passthrough, mutating the caller's "user memory"
    /// must NOT change what the kernel will read. (In real life this is a
    /// concurrent thread overwriting the path between check and use.)
    #[test]
    fn copy_passthrough_isolates_from_user_memory() {
        let mut user_mem: Vec<u16> = "abc".encode_utf16().collect();
        let mut user_ustr = UNICODE_STRING {
            Length: (user_mem.len() * 2) as u16,
            MaximumLength: (user_mem.len() * 2) as u16,
            Buffer: user_mem.as_mut_ptr(),
        };
        let orig = fake_orig(&mut user_ustr);

        let mut h = unsafe { HookedAttrs::copy_passthrough(&orig).unwrap() };

        // Now the attacker overwrites user-memory mid-syscall.
        for c in user_mem.iter_mut() {
            *c = b'X' as u16;
        }

        // Recover what the kernel would see via the hook's pointer.
        unsafe {
            let attrs_ptr = h.as_ptr_mut();
            let attrs = &*attrs_ptr;
            assert!(!attrs.ObjectName.is_null());
            let kernel_ustr = &*attrs.ObjectName;
            let n = (kernel_ustr.Length / 2) as usize;
            assert_eq!(n, 3);
            let kernel_slice = std::slice::from_raw_parts(kernel_ustr.Buffer, n);
            // Hook-owned copy is unchanged — TOCTOU defense holds.
            assert_eq!(kernel_slice, &['a' as u16, 'b' as u16, 'c' as u16][..]);
        }
    }

    /// Audit M-S2 — reject oversized inputs so we don't allocate
    /// megabytes per syscall on hostile input. The kernel will reject
    /// these too on its own length check, so falling through to the
    /// original pointer is a safe degradation.
    #[test]
    fn copy_passthrough_rejects_oversized() {
        let mut user_ustr = UNICODE_STRING {
            // 65535 bytes — exceeds MAX_PASSTHROUGH_LEN_BYTES (65534).
            Length: 65535,
            MaximumLength: 65535,
            Buffer: 0x1 as *mut u16, // never read because length check fires first
        };
        let orig = fake_orig(&mut user_ustr);
        let result = unsafe { HookedAttrs::copy_passthrough(&orig) };
        assert!(result.is_none());

        // Boundary check: 65534 is allowed (provided Buffer is real).
        let mut payload: Vec<u16> = vec![b'a' as u16; (MAX_PASSTHROUGH_LEN_BYTES / 2) as usize];
        let mut user_ustr2 = UNICODE_STRING {
            Length: MAX_PASSTHROUGH_LEN_BYTES,
            MaximumLength: MAX_PASSTHROUGH_LEN_BYTES,
            Buffer: payload.as_mut_ptr(),
        };
        let orig2 = fake_orig(&mut user_ustr2);
        let result2 = unsafe { HookedAttrs::copy_passthrough(&orig2) };
        assert!(result2.is_some());
    }

    /// Audit M-S2 — reject inputs we have nothing to copy.
    #[test]
    fn copy_passthrough_rejects_empty_inputs() {
        // Null ObjectName.
        let orig_null = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: std::ptr::null_mut(),
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        assert!(unsafe { HookedAttrs::copy_passthrough(&orig_null) }.is_none());

        // Non-null ObjectName but null Buffer.
        let mut empty_ustr = UNICODE_STRING {
            Length: 4,
            MaximumLength: 4,
            Buffer: std::ptr::null_mut(),
        };
        let orig_nullbuf = fake_orig(&mut empty_ustr);
        assert!(unsafe { HookedAttrs::copy_passthrough(&orig_nullbuf) }.is_none());

        // Length zero.
        let mut payload: Vec<u16> = vec![b'a' as u16, b'b' as u16];
        let mut zero_ustr = UNICODE_STRING {
            Length: 0,
            MaximumLength: 4,
            Buffer: payload.as_mut_ptr(),
        };
        let orig_zerolen = fake_orig(&mut zero_ustr);
        assert!(unsafe { HookedAttrs::copy_passthrough(&orig_zerolen) }.is_none());
    }

    /// Audit M-S2 — verify the copy carries every non-path field verbatim
    /// so the kernel sees an identical context except for the Buffer
    /// pointer.
    #[test]
    fn passthrough_attrs_other_fields_preserved() {
        let mut user_mem: Vec<u16> = "xy".encode_utf16().collect();
        let mut user_ustr = UNICODE_STRING {
            Length: (user_mem.len() * 2) as u16,
            MaximumLength: (user_mem.len() * 2) as u16,
            Buffer: user_mem.as_mut_ptr(),
        };
        let orig = fake_orig(&mut user_ustr);
        let mut h = unsafe { HookedAttrs::copy_passthrough(&orig).unwrap() };
        let attrs_ptr = h.as_ptr_mut();
        // SAFETY: pointer valid for the lifetime of h.
        let attrs = unsafe { &*attrs_ptr };
        assert_eq!(attrs.RootDirectory as usize, 0x1234_5678);
        assert_eq!(attrs.Attributes, 0x42);
        assert_eq!(attrs.SecurityDescriptor as usize, 0xAAAA_BBBB);
        assert_eq!(attrs.SecurityQualityOfService as usize, 0xCCCC_DDDD);
        assert_eq!(attrs.Length as usize, std::mem::size_of::<OBJECT_ATTRIBUTES>());
    }

    /// The Box-/move-resilience case: even after moving the HookedAttrs,
    /// `as_ptr_mut()` patches ObjectName to the current address of ustr
    /// in the (new) self. Vec<u16>'s heap allocation also stays put across
    /// the move, so Buffer remains valid.
    #[test]
    fn as_ptr_mut_after_move_is_coherent() {
        let orig = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: std::ptr::null_mut(),
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let h1 = unsafe { HookedAttrs::redirect(&orig, r"C:\a.txt", false) };
        // Move h1 into h2.
        let mut h2 = h1;
        let ptr = h2.as_ptr_mut();
        let attrs = unsafe { &*ptr };
        // ObjectName must point at &h2.ustr after the move.
        assert_eq!(attrs.ObjectName as usize, &h2.ustr as *const _ as usize);
        // Buffer must still point into h2.nt_buf.
        let ustr = unsafe { &*attrs.ObjectName };
        assert_eq!(ustr.Buffer as *const u16, h2.nt_buf.as_ptr());
    }
}
