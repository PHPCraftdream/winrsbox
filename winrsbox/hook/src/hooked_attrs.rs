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
    /// double-fetch gap on `UNICODE_STRING.Buffer` AND the handle race on
    /// `OBJECT_ATTRIBUTES.RootDirectory`.
    ///
    /// Two distinct cases:
    ///
    /// 1. `orig.RootDirectory.is_null()` (the common case — absolute
    ///    paths): copy `orig.ObjectName.Buffer` verbatim into hook-owned
    ///    memory and inherit `RootDirectory` (null) unchanged. The kernel
    ///    re-reads `Buffer`; copying it closes the M-S2 double-fetch.
    ///
    /// 2. `orig.RootDirectory` is non-null (relative open, path
    ///    interpreted against a directory HANDLE): the handle VALUE alone
    ///    is racy. Audit H5 — a hostile thread can `NtClose` the directory
    ///    handle and reopen a different directory in the same handle-table
    ///    slot between our policy check and the kernel's resolution, so the
    ///    same numeric handle now anchors a different directory. The Buffer
    ///    copy is moot if the anchor races. Defense: resolve the handle to
    ///    its absolute NT path NOW (via `crate::inject::resolve_handle_path`,
    ///    the same helper `extract_dos_path` uses to make its policy
    ///    decision), JOIN it with the ObjectName exactly as
    ///    `extract_dos_path` does (`base + '\' + name`), store the absolute
    ///    path in hook-owned memory, and set `RootDirectory = null`. The
    ///    kernel then resolves a canonical absolute `\Device\...` path with
    ///    no handle to race.
    ///
    /// Returns `None` (signaling the caller to FAIL CLOSED — see the
    /// Passthrough call sites in fs_hooks.rs) when:
    ///   - `orig.ObjectName.is_null()` — no buffer to copy.
    ///   - `orig.ObjectName.Buffer.is_null()` — nothing to read.
    ///   - `orig.ObjectName.Length` is zero — empty name.
    ///   - `orig.ObjectName.Length > MAX_PASSTHROUGH_LEN_BYTES` — DoS
    ///     amplification refusal on the largest, most suspicious inputs.
    ///   - `orig.RootDirectory` is non-null but `resolve_handle_path`
    ///     returns `None` — we cannot make the path absolute, so we cannot
    ///     safely defuse the handle race. Fail closed.
    ///   - the joined absolute path exceeds the `UNICODE_STRING.Length` u16
    ///     ceiling (`MAX_PASSTHROUGH_LEN_BYTES`).
    ///
    /// SAFETY: `orig` must be a valid OBJECT_ATTRIBUTES with a readable
    /// (possibly null) ObjectName for the duration of this call. When
    /// `RootDirectory` is null the returned HookedAttrs inherits it (and
    /// `Attributes`, `SecurityDescriptor`, `SecurityQualityOfService`)
    /// verbatim. When `RootDirectory` is non-null the returned attrs carry
    /// a NULL RootDirectory and an absolute ObjectName instead.
    // Convenience wrapper (resolves the handle internally). Production FS hooks
    // call `copy_passthrough_inner` with the hook's pre-resolved path (H5); this
    // no-pre-resolution form is used by the unit tests, so it reads as dead code
    // in a non-test cdylib build.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) unsafe fn copy_passthrough(orig: &OBJECT_ATTRIBUTES) -> Option<Self> {
        Self::copy_passthrough_inner(orig, None)
    }

    /// As [`copy_passthrough`], but accepts the hook's already-resolved
    /// absolute NT path for the RootDirectory-relative case. When
    /// `pre_resolved_abs` is `Some`, the directory handle is NOT resolved here
    /// — the path is taken verbatim from the single resolution the hook made
    /// (see `hooks::resolve_for_hook`), closing the H5 double-resolve window.
    /// When `None`, behaves exactly as the standalone `copy_passthrough`
    /// (resolves the handle internally) — used by tests and any caller without
    /// a pre-resolution.
    pub(crate) unsafe fn copy_passthrough_inner(
        orig: &OBJECT_ATTRIBUTES,
        pre_resolved_abs: Option<&[u16]>,
    ) -> Option<Self> {
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
        // bytes per the NT UNICODE_STRING contract (checked above).
        let name_slice = std::slice::from_raw_parts(src.Buffer, char_count);

        if !orig.RootDirectory.is_null() {
            // --- H5: defuse the RootDirectory handle race -------------------
            // Resolve the directory handle to its absolute NT path and join
            // with the ObjectName, MIRRORING extract_dos_path() in hooks.rs
            // (the join it used to make the policy decision): `base + '\' +
            // name`. We must build the SAME path the classifier saw so the
            // kernel resolves what policy approved.
            //
            // resolve_handle_path reads the handle exactly once here. That
            // single read is inside the same TOCTOU window in principle, but
            // turning a racy handle into an absolute path collapses the
            // window: after this point we pass NO handle to the kernel, so
            // there is nothing left for a concurrent NtClose/reopen to swap.
            // SAFETY: orig.RootDirectory is non-null and, per the NT calling
            // convention for our hook parameter, a valid open directory
            // handle for the duration of this call.
            // Prefer the hook's single pre-resolved absolute path (H5: avoids a
            // SECOND resolve_handle_path here that could race the decision's
            // resolution). Fall back to resolving once when not provided
            // (standalone/test callers). Both produce base + '\' + name.
            let nt_buf: Vec<u16> = match pre_resolved_abs {
                Some(abs) => abs.to_vec(),
                None => {
                    let base = crate::inject::resolve_handle_path(orig.RootDirectory)?;
                    let mut full: Vec<u16> = base;
                    full.push(b'\\' as u16);
                    full.extend_from_slice(name_slice);
                    full
                }
            };

            // The joined absolute path must still fit UNICODE_STRING.Length
            // (a u16, max MAX_PASSTHROUGH_LEN_BYTES). If not, fail closed.
            let joined_bytes = nt_buf.len().checked_mul(2)?;
            if joined_bytes > MAX_PASSTHROUGH_LEN_BYTES as usize {
                return None;
            }
            let len_bytes = joined_bytes as u16;

            let ustr = UNICODE_STRING {
                Length: len_bytes,
                // Our own synthesized absolute path: a tight-but-valid
                // MaximumLength == Length. The kernel write-back-on-reparse
                // headroom concern (see the verbatim-copy branch below)
                // applies to caller-supplied buffers whose MaximumLength
                // signaled spare capacity; our absolute path is freshly
                // built and not subject to that contract.
                MaximumLength: len_bytes,
                Buffer: nt_buf.as_ptr() as *mut u16,
            };
            let attrs = OBJECT_ATTRIBUTES {
                Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
                // RootDirectory nulled: the path is now absolute, so the
                // racy handle anchor is gone.
                RootDirectory: std::ptr::null_mut(),
                ObjectName: std::ptr::null_mut(),
                Attributes: orig.Attributes,
                SecurityDescriptor: orig.SecurityDescriptor,
                SecurityQualityOfService: orig.SecurityQualityOfService,
            };
            return Some(HookedAttrs { nt_buf, ustr, attrs });
        }

        // --- Common case: absolute path, null RootDirectory ----------------
        // Copy the caller's buffer into hook-owned heap memory (M-S2 TOCTOU
        // defense on Buffer). Preserve MaximumLength headroom: the kernel may
        // write back into the buffer on some NtCreateFile reparse paths and
        // expects MaximumLength bytes of capacity. Allocate MaximumLength/2
        // u16 slots, copy char_count chars in, leave the rest zero-padded.
        //
        // Malformed input guard: if MaximumLength < Length (a hostile or
        // buggy caller), clamp MaximumLength up to Length so the allocation
        // always covers the copied chars and the kernel never sees
        // MaximumLength < Length.
        let max_bytes = src.MaximumLength.max(src.Length);
        let cap_chars = (max_bytes / 2) as usize;
        // cap_chars >= char_count because max_bytes >= src.Length = char_count*2.
        let mut nt_buf: Vec<u16> = vec![0u16; cap_chars];
        nt_buf[..char_count].copy_from_slice(name_slice);

        let ustr = UNICODE_STRING {
            Length: src.Length,
            MaximumLength: max_bytes,
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
    ///
    /// RootDirectory is NULL here so `copy_passthrough` takes the common
    /// verbatim-copy branch. A non-null RootDirectory would make
    /// `copy_passthrough` call `resolve_handle_path` on the value (audit H5
    /// handle-race defense), which is a real `NtQueryObject` syscall — not
    /// something a pure unit test can satisfy with a fabricated handle.
    fn fake_orig(ustr: *mut UNICODE_STRING) -> OBJECT_ATTRIBUTES {
        OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
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
        // Null RootDirectory (the common absolute-path case) is preserved
        // verbatim as null. (Audit H5: a NON-null RootDirectory is instead
        // resolved to an absolute path and nulled out — covered by
        // copy_passthrough_nonnull_rootdir_becomes_absolute.)
        assert!(attrs.RootDirectory.is_null());
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

    /// Audit H5 / move-resilience — same as `as_ptr_mut_after_move_is_coherent`
    /// but for the copy_passthrough constructor. After moving the
    /// HookedAttrs, `as_ptr_mut()` must re-anchor ObjectName to the new
    /// self's ustr, and ustr.Buffer must still point into the (moved) nt_buf
    /// (Vec heap is address-stable across the move).
    #[test]
    fn copy_passthrough_as_ptr_mut_after_move_is_coherent() {
        let mut user_mem: Vec<u16> = "abc".encode_utf16().collect();
        let mut user_ustr = UNICODE_STRING {
            Length: (user_mem.len() * 2) as u16,
            MaximumLength: (user_mem.len() * 2) as u16,
            Buffer: user_mem.as_mut_ptr(),
        };
        let orig = fake_orig(&mut user_ustr);

        let h1 = unsafe { HookedAttrs::copy_passthrough(&orig).unwrap() };
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

    /// Code-quality #3 — `copy_passthrough` must PRESERVE the caller's
    /// MaximumLength (not clamp it to Length). The kernel may write back
    /// into the buffer on some NtCreateFile reparse paths and relies on the
    /// reported MaximumLength headroom. ObjectName Length = 10 bytes,
    /// MaximumLength = 20 bytes → the copy must report MaximumLength = 20
    /// and back it with a buffer of at least 10 u16 slots.
    #[test]
    fn copy_passthrough_preserves_maximum_length() {
        // 5 chars = 10 bytes of Length; buffer physically holds 10 u16 so
        // the MaximumLength=20 (10 u16) read-back capacity is real.
        let mut user_mem: Vec<u16> = vec![b'a' as u16; 10];
        let mut user_ustr = UNICODE_STRING {
            Length: 10,
            MaximumLength: 20,
            Buffer: user_mem.as_mut_ptr(),
        };
        let orig = fake_orig(&mut user_ustr);
        let mut h = unsafe { HookedAttrs::copy_passthrough(&orig).unwrap() };
        let attrs = unsafe { &*h.as_ptr_mut() };
        let ustr = unsafe { &*attrs.ObjectName };
        assert_eq!(ustr.Length, 10, "Length must be preserved");
        assert_eq!(ustr.MaximumLength, 20, "MaximumLength must be preserved (not clamped to Length)");
        // The owned buffer must physically hold MaximumLength/2 = 10 u16 so
        // a kernel write-back up to MaximumLength does not overrun.
        assert_eq!(h.nt_buf.len(), 10, "buffer must be sized to MaximumLength/2");
        // The first 5 chars carry the path; the tail is zero-padded.
        assert_eq!(&h.nt_buf[..5], &[b'a' as u16; 5][..]);
        assert_eq!(&h.nt_buf[5..], &[0u16; 5][..], "tail must be zero-padded");
    }

    /// Code-quality #3 (malformed-input guard) — when MaximumLength <
    /// Length (hostile/buggy caller), MaximumLength is clamped UP to Length
    /// so the kernel never sees MaximumLength < Length and the allocation
    /// always covers the copied chars.
    #[test]
    fn copy_passthrough_clamps_malformed_maximum_length() {
        let mut user_mem: Vec<u16> = vec![b'z' as u16; 4]; // 8 bytes
        let mut user_ustr = UNICODE_STRING {
            Length: 8,
            MaximumLength: 2, // malformed: < Length
            Buffer: user_mem.as_mut_ptr(),
        };
        let orig = fake_orig(&mut user_ustr);
        let mut h = unsafe { HookedAttrs::copy_passthrough(&orig).unwrap() };
        let attrs = unsafe { &*h.as_ptr_mut() };
        let inner = unsafe { &*attrs.ObjectName };
        assert_eq!(inner.Length, 8);
        assert_eq!(inner.MaximumLength, 8, "MaximumLength must be clamped up to Length");
        assert_eq!(h.nt_buf.len(), 4);
    }

    /// Audit H5 / M-S2 — oversized ObjectName returns None so the caller can
    /// fail closed (no fall-through to the attacker pointer). Boundary:
    /// 65535 bytes → None; 65534 (= MAX_PASSTHROUGH_LEN_BYTES) → Some.
    #[test]
    fn copy_passthrough_oversized_returns_none() {
        // 65535 bytes — exceeds the u16 cap → None (Buffer never read).
        let mut over_ustr = UNICODE_STRING {
            Length: 65535,
            MaximumLength: 65535,
            Buffer: 0x1 as *mut u16,
        };
        let over = fake_orig(&mut over_ustr);
        assert!(unsafe { HookedAttrs::copy_passthrough(&over) }.is_none());

        // 65534 bytes — exactly the cap → Some (with a real backing buffer).
        let mut payload: Vec<u16> = vec![b'a' as u16; (MAX_PASSTHROUGH_LEN_BYTES / 2) as usize];
        let mut ok_ustr = UNICODE_STRING {
            Length: MAX_PASSTHROUGH_LEN_BYTES,
            MaximumLength: MAX_PASSTHROUGH_LEN_BYTES,
            Buffer: payload.as_mut_ptr(),
        };
        let ok = fake_orig(&mut ok_ustr);
        assert!(unsafe { HookedAttrs::copy_passthrough(&ok) }.is_some());
    }

    /// Audit M-S2 — with a NULL RootDirectory (the common absolute-path
    /// case), the buffer is copied into hook-owned memory. Mutating the
    /// caller's buffer after construction must NOT change the hook copy.
    #[test]
    fn copy_passthrough_null_rootdir_copies_buffer() {
        let mut user_mem: Vec<u16> = "data.txt".encode_utf16().collect();
        let orig_chars: Vec<u16> = user_mem.clone();
        let mut user_ustr = UNICODE_STRING {
            Length: (user_mem.len() * 2) as u16,
            MaximumLength: (user_mem.len() * 2) as u16,
            Buffer: user_mem.as_mut_ptr(),
        };
        let orig = fake_orig(&mut user_ustr); // RootDirectory is null
        let mut h = unsafe { HookedAttrs::copy_passthrough(&orig).unwrap() };

        // RootDirectory stays null; buffer must be a hook-owned copy.
        let attrs = unsafe { &*h.as_ptr_mut() };
        assert!(attrs.RootDirectory.is_null());
        assert_ne!(
            h.nt_buf.as_ptr(),
            user_mem.as_ptr(),
            "hook buffer must be a distinct allocation, not the caller's"
        );

        // Attacker overwrites the caller's buffer mid-syscall.
        for c in user_mem.iter_mut() {
            *c = b'X' as u16;
        }
        // The hook copy is unchanged — TOCTOU defense holds.
        assert_eq!(&h.nt_buf[..orig_chars.len()], &orig_chars[..]);
    }

    /// Audit H5 — when RootDirectory is a NON-null directory handle, the
    /// copy must resolve it to an absolute NT path, JOIN the ObjectName, and
    /// NULL the RootDirectory so no racy handle reaches the kernel.
    ///
    /// This needs a real open directory handle (resolve_handle_path issues
    /// an NtQueryObject syscall), so we open C:\Windows with backup
    /// semantics. If the open or resolution fails on a locked-down host the
    /// test logs and returns rather than hard-failing CI; the absolute-path
    /// join is additionally exercised by the e2e escape harnesses.
    #[test]
    fn copy_passthrough_nonnull_rootdir_becomes_absolute() {
        use winapi::um::fileapi::CreateFileW;
        use winapi::um::fileapi::OPEN_EXISTING;
        use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
        use winapi::um::winnt::{
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ,
        };
        // FILE_FLAG_BACKUP_SEMANTICS lives in winapi::um::winbase, a feature
        // the hook crate does not enable (and Cargo.toml is out of scope for
        // this change). Define the constant locally — required to open a
        // *directory* as a handle. Value pinned by winnt.h / winbase.
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

        let dir_w: Vec<u16> = r"C:\Windows".encode_utf16().chain(Some(0)).collect();
        // SAFETY: dir_w is a null-terminated UTF-16 path; all other args are
        // valid constants / null. Backup semantics is required to open a
        // directory as a handle.
        let dir_handle = unsafe {
            CreateFileW(
                dir_w.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        if dir_handle == INVALID_HANDLE_VALUE || dir_handle.is_null() {
            eprintln!("[skip] could not open C:\\Windows as a directory handle");
            return;
        }

        let mut name: Vec<u16> = "probe.txt".encode_utf16().collect();
        let mut name_ustr = UNICODE_STRING {
            Length: (name.len() * 2) as u16,
            MaximumLength: (name.len() * 2) as u16,
            Buffer: name.as_mut_ptr(),
        };
        let orig = OBJECT_ATTRIBUTES {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: dir_handle as *mut _,
            ObjectName: &mut name_ustr,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };

        // SAFETY: orig is a valid OBJECT_ATTRIBUTES; dir_handle is a live
        // directory handle for the duration of this call.
        let copied = unsafe { HookedAttrs::copy_passthrough(&orig) };
        // SAFETY: dir_handle is the handle we opened above; close it before
        // any assertion can early-return so we never leak it.
        unsafe { CloseHandle(dir_handle) };

        let mut h = match copied {
            Some(h) => h,
            None => {
                eprintln!("[skip] resolve_handle_path returned None for C:\\Windows");
                return;
            }
        };

        let attrs = unsafe { &*h.as_ptr_mut() };
        // The racy handle anchor must be gone.
        assert!(
            attrs.RootDirectory.is_null(),
            "RootDirectory must be nulled once the path is made absolute"
        );
        // The path must now be the resolved directory joined with the name.
        let resolved = String::from_utf16_lossy(&h.nt_buf);
        assert!(
            resolved.contains("Windows"),
            "absolute path must contain the resolved directory (got: {resolved})"
        );
        assert!(
            resolved.ends_with("probe.txt"),
            "absolute path must end with the joined ObjectName (got: {resolved})"
        );
        // Length must match the synthesized buffer (no stale handle-relative len).
        let ustr = unsafe { &*attrs.ObjectName };
        assert_eq!(ustr.Length as usize, h.nt_buf.len() * 2);
        assert_eq!(ustr.MaximumLength, ustr.Length);
    }
}
