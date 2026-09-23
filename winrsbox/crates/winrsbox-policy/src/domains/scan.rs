// Code integrity scanner — detects direct syscall instructions in PE images.
//
// Uses iced-x86 for accurate x86-64 instruction decoding (avoids false positives
// from byte patterns like 0F 05 appearing as immediate operands).
//
// Crate version assumed:
//   iced-x86 = "1"  (no_std + decoder, no encoder)

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyscallKind {
    Syscall,  // 0F 05 — x86-64 fast syscall
    Sysenter, // 0F 34 — legacy fast syscall
    Int2e,    // CD 2E — legacy Windows syscall via interrupt
}

impl std::fmt::Display for SyscallKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Syscall => f.write_str("syscall"),
            Self::Sysenter => f.write_str("sysenter"),
            Self::Int2e => f.write_str("int 2eh"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyscallHit {
    pub offset: usize,
    pub kind: SyscallKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeTextSection {
    pub virtual_address: u32,
    pub virtual_size: u32,
}

/// Longest possible x86-64 instruction. Also bounds the alternate-entry
/// decode windows below.
pub const MAX_INSTRUCTION_LEN: usize = 15;

/// Linear-sweep decode from EVERY entry offset `0..=MAX_INSTRUCTION_LEN`
/// (each non-zero entry bounded to a `2 * MAX_INSTRUCTION_LEN`-byte window),
/// merged with [`find_direct_syscalls`]'s canonical offset-0 sweep.
///
/// Why: the canonical sweep alone has a decode-AMBIGUITY hole (XA review S06,
/// gap 2). Bytes that the offset-0 parse consumes as an immediate operand can
/// be a real syscall when execution enters at a different alignment — the
/// test `mov_with_immediate_containing_syscall_bytes_no_hit` shows a
/// `mov rax, 0x050F` whose `0F 05` bytes the offset-0 decode swallows, while
/// a `jmp` directly onto those bytes executes a real `syscall`. A decode
/// pass entering exactly on those bytes flags them.
///
/// What this DOES guarantee:
///   - buffers of at most MAX_INSTRUCTION_LEN bytes (short trampolines and
///     stubs): every byte offset is an entry, so EVERY occurrence of the
///     syscall byte patterns is flagged regardless of alignment;
///   - longer buffers: additionally any pattern that is an instruction
///     boundary of a linear decode starting within the first
///     MAX_INSTRUCTION_LEN bytes (bounded windows keep the overhead O(1)
///     per call on top of the canonical sweep).
///
/// What this does NOT guarantee — KNOWN LIMITATION, recorded deliberately
/// instead of silently narrowed (XA review S06): a pattern buried in an
/// immediate deeper than the entry windows is still NOT flagged, although a
/// direct `jmp` onto its bytes would execute it. Closing that fully would
/// require either (a) flagging every raw byte occurrence — rejected: ordinary
/// machine-code byte streams contain any fixed 2-byte pattern roughly every
/// 2^16 positions, so real compiler code would be killed in bursts, which is
/// exactly why decode-based scanning exists (see the module doc comment) — or
/// (b) full control-flow/reachability analysis of hostile memory, out of
/// scope for a mitigation layer. The scanner is therefore a MITIGATION, not
/// a formal proof that no direct-syscall entry point can execute; the open
/// question of a stronger sound mechanism is recorded here rather than
/// papered over.
pub fn find_direct_syscalls_multi_entry(bytes: &[u8], base_addr: u64) -> Vec<SyscallHit> {
    let mut hits = find_direct_syscalls(bytes, base_addr);
    let entries = bytes.len().min(MAX_INSTRUCTION_LEN + 1);
    let window = 2 * MAX_INSTRUCTION_LEN;
    for entry in 1..entries {
        let end = (entry + window).min(bytes.len());
        for hit in find_direct_syscalls(&bytes[entry..end], base_addr + entry as u64) {
            hits.push(SyscallHit { offset: hit.offset + entry, kind: hit.kind });
        }
    }
    hits.sort_by_key(|h| h.offset);
    hits.dedup_by_key(|h| h.offset);
    hits
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

/// Classify one decoded instruction: Some(kind) when it is a direct
/// syscall (syscall / sysenter / int 2eh). Single-sourced so the
/// Vec-collecting sweep of [`find_direct_syscalls`] and the early-exit
/// predicate's sweep cannot drift apart.
fn syscall_kind(instr: &Instruction) -> Option<SyscallKind> {
    match instr.mnemonic() {
        Mnemonic::Syscall => Some(SyscallKind::Syscall),
        Mnemonic::Sysenter => Some(SyscallKind::Sysenter),
        Mnemonic::Int => {
            // INT imm8 — check if imm is 0x2e
            if instr.immediate8() == 0x2e {
                Some(SyscallKind::Int2e)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// A syscall pattern decoded within this many instructions after an INVALID
/// decode is data, not code, unless it has the canonical Windows x64 stub
/// setup (`mov r10, rcx; mov eax, imm32; syscall`). The suppression avoids
/// flagging jump/lookup tables that MSVC/LLVM place inside `.text`. Observed:
/// codex.exe (230 MB `.text`) has `…0f 0f 04 0f 0f 05…` in a byte table,
/// reached through a run of INVALID decodes. Buffers of at most
/// MAX_INSTRUCTION_LEN bytes are exempt.
///
/// An exact byte-pattern check also catches this stub when the decoder's
/// INVALID instruction consumes its first byte. Other stub forms can still
/// be suppressed when they occur within the lookback window;
/// this remains a mitigation, not a proof that every executable entry is
/// found (see [`find_direct_syscalls_multi_entry`]).
pub const DATA_CONTEXT_LOOKBACK: usize = 4;

/// Offset of the syscall in `mov r10, rcx; mov eax, imm32; syscall`.
fn canonical_stub_syscalls(bytes: &[u8]) -> impl Iterator<Item = usize> + '_ {
    bytes.windows(10).enumerate().filter_map(|(offset, window)| {
        (window.starts_with(&[0x4c, 0x8b, 0xd1, 0xb8])
            && window[8..] == [0x0f, 0x05])
            .then_some(offset + 8)
    })
}

/// Tracks decoded instructions since the last INVALID one.
struct DataContext {
    exempt: bool,
    since_invalid: usize,
    after_mov_r10_rcx: bool,
    after_stub_setup: bool,
}

impl DataContext {
    fn new(len: usize) -> Self {
        Self {
            exempt: len <= MAX_INSTRUCTION_LEN,
            since_invalid: DATA_CONTEXT_LOOKBACK,
            after_mov_r10_rcx: false,
            after_stub_setup: false,
        }
    }

    /// Classify `instr` and advance the context.
    fn hit(&mut self, instr: &Instruction) -> Option<SyscallKind> {
        if instr.is_invalid() {
            self.since_invalid = 0;
            self.after_mov_r10_rcx = false;
            self.after_stub_setup = false;
            return None;
        }

        let is_syscall = syscall_kind(instr);
        let canonical_stub = self.after_stub_setup && is_syscall == Some(SyscallKind::Syscall);
        let kind = is_syscall.filter(|_| {
            self.exempt || self.since_invalid >= DATA_CONTEXT_LOOKBACK || canonical_stub
        });

        self.after_stub_setup = self.after_mov_r10_rcx && is_mov_eax_imm32(instr);
        self.after_mov_r10_rcx = is_mov_r10_rcx(instr);
        self.since_invalid = self.since_invalid.saturating_add(1);
        kind
    }
}

fn is_mov_r10_rcx(instr: &Instruction) -> bool {
    instr.mnemonic() == Mnemonic::Mov
        && instr.op_count() == 2
        && instr.op_kind(0) == OpKind::Register
        && instr.op_register(0) == Register::R10
        && instr.op_kind(1) == OpKind::Register
        && instr.op_register(1) == Register::RCX
}

fn is_mov_eax_imm32(instr: &Instruction) -> bool {
    instr.mnemonic() == Mnemonic::Mov
        && instr.op_count() == 2
        && instr.op_kind(0) == OpKind::Register
        && instr.op_register(0) == Register::EAX
        && instr.op_kind(1) == OpKind::Immediate32
}

/// Disassemble `bytes` as x86-64 instructions starting at `base_addr` and
/// return all direct syscall instructions found.
///
/// This is *linear sweep* disassembly — it decodes from byte 0 sequentially.
/// iced-x86 returns a 1-byte INVALID instruction for undecodable bytes and
/// continues; patterns right after INVALID decodes are skipped as data except
/// for the canonical Windows syscall stub (see [`DATA_CONTEXT_LOOKBACK`]).
pub fn find_direct_syscalls(bytes: &[u8], base_addr: u64) -> Vec<SyscallHit> {
    let mut hits = Vec::new();
    let mut ctx = DataContext::new(bytes.len());
    let mut decoder = Decoder::with_ip(64, bytes, base_addr, DecoderOptions::NONE);
    while decoder.can_decode() {
        let pos = decoder.position();
        let instr = decoder.decode();
        if let Some(k) = ctx.hit(&instr) {
            hits.push(SyscallHit { offset: pos, kind: k });
        }
    }
    hits.extend(canonical_stub_syscalls(bytes).map(|offset| SyscallHit {
        offset,
        kind: SyscallKind::Syscall,
    }));
    hits.sort_by_key(|hit| hit.offset);
    hits.dedup_by_key(|hit| hit.offset);
    hits
}

/// Early-exiting variant of the [`find_direct_syscalls`] sweep, used only
/// by [`has_direct_syscall`]; classification is shared via [`DataContext`].
fn sweep_has_direct_syscall(bytes: &[u8], base_addr: u64) -> bool {
    let mut ctx = DataContext::new(bytes.len());
    let mut decoder = Decoder::with_ip(64, bytes, base_addr, DecoderOptions::NONE);
    while decoder.can_decode() {
        if ctx.hit(&decoder.decode()).is_some() {
            return true;
        }
    }
    false
}

/// Boolean twin of [`find_direct_syscalls_multi_entry`]: true iff that
/// function would report at least one hit. It runs the SAME decode passes
/// — the canonical offset-0 sweep of the WHOLE buffer plus the
/// alternate-entry windows (`entry in 1..min(bytes.len(),
/// MAX_INSTRUCTION_LEN + 1)`, each bounded to
/// `bytes[entry..min(entry + 2 * MAX_INSTRUCTION_LEN, len)]` at
/// `base_addr + entry`) — so the S06 guarantees (full-range sweep,
/// multi-entry decode, no scan caps) hold by construction: the shared
/// `syscall_kind` classifier and identical sweep structure keep the two
/// versions from drifting. Early exit happens only AFTER a hit has been
/// found, so it can never skip an undecoded region; the win is that the
/// remaining passes after a hit are not decoded and no Vec is built.
pub fn has_direct_syscall(bytes: &[u8], base_addr: u64) -> bool {
    if sweep_has_direct_syscall(bytes, base_addr) {
        return true;
    }
    if canonical_stub_syscalls(bytes).next().is_some() {
        return true;
    }
    let entries = bytes.len().min(MAX_INSTRUCTION_LEN + 1);
    let window = 2 * MAX_INSTRUCTION_LEN;
    for entry in 1..entries {
        let end = (entry + window).min(bytes.len());
        if sweep_has_direct_syscall(&bytes[entry..end], base_addr + entry as u64) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// PE parser — find .text section
// ---------------------------------------------------------------------------

const DOS_MAGIC: u16 = 0x5A4D; // "MZ"
const NT_MAGIC: u32 = 0x00004550; // "PE\0\0"

/// Section-characteristic flag: the section may contain executable code.
/// XA review S06 (gap 3): scanning only the section literally named ".text"
/// misses additional executable sections — ".text" is a convention, not a
/// contract; a PE can carry any number of IMAGE_SCN_MEM_EXECUTE sections.
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

fn read_u16_le(buf: &[u8], offset: usize) -> Option<u16> {
    buf.get(offset..offset + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn read_u32_le(buf: &[u8], offset: usize) -> Option<u32> {
    buf.get(offset..offset + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// One PE section worth scanning: its raw 8-byte name (not necessarily
/// NUL-terminated), RVA and virtual size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeExecutableSection {
    pub name: [u8; 8],
    pub virtual_address: u32,
    pub virtual_size: u32,
}

/// Raw section-table entry.
struct RawSection {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    characteristics: u32,
}

/// Parse the PE section table. Returns None on any malformed or truncated
/// header (same strictness as the previous `.text`-only helper).
fn pe_sections(pe_bytes: &[u8]) -> Option<Vec<RawSection>> {
    // DOS header: magic at 0, e_lfanew at 0x3C
    if read_u16_le(pe_bytes, 0)? != DOS_MAGIC {
        return None;
    }
    let e_lfanew = read_u32_le(pe_bytes, 0x3C)? as usize;

    // NT signature
    if read_u32_le(pe_bytes, e_lfanew)? != NT_MAGIC {
        return None;
    }

    // COFF File Header (20 bytes) at e_lfanew + 4
    let coff = e_lfanew + 4;
    let num_sections = read_u16_le(pe_bytes, coff + 2)? as usize;
    let size_optional = read_u16_le(pe_bytes, coff + 16)? as usize;

    // Section table starts after optional header
    let section_table = coff + 20 + size_optional;
    const SECTION_HEADER_SIZE: usize = 40;

    let mut sections = Vec::with_capacity(num_sections.min(96));
    for i in 0..num_sections {
        let s = section_table + i * SECTION_HEADER_SIZE;
        let name_bytes = pe_bytes.get(s..s + 8)?;
        let mut name = [0u8; 8];
        name.copy_from_slice(name_bytes);
        sections.push(RawSection {
            name,
            virtual_size: read_u32_le(pe_bytes, s + 8)?,
            virtual_address: read_u32_le(pe_bytes, s + 12)?,
            characteristics: read_u32_le(pe_bytes, s + 36)?,
        });
    }
    Some(sections)
}

/// Every section carrying IMAGE_SCN_MEM_EXECUTE, in section-table order.
///
/// XA review S06 (gap 3): callers must scan ALL of these, not just the one
/// named ".text" — a binary can have clean `.text` plus an additional
/// executable section; only-.text scanning left that code unscanned in the
/// pre-launch scan, the child image scan and the MapView DLL scan.
pub fn pe_executable_sections(pe_bytes: &[u8]) -> Vec<PeExecutableSection> {
    pe_sections(pe_bytes)
        .map(|sections| {
            sections
                .into_iter()
                .filter(|s| s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
                .map(|s| PeExecutableSection {
                    name: s.name,
                    virtual_address: s.virtual_address,
                    virtual_size: s.virtual_size,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Parse a buffer containing the PE headers (DOS + NT + sections) and return
/// the `.text` section's RVA and virtual size.
///
/// Buffer must contain at least the DOS header, NT headers, and section table.
/// Typically 4 KiB from the image base is enough.
///
/// Prefer [`pe_executable_sections`]: `.text` is only one of potentially
/// several executable sections (XA review S06, gap 3). This helper is kept
/// for callers that specifically need the conventional `.text` section.
pub fn pe_text_section(pe_bytes: &[u8]) -> Option<PeTextSection> {
    pe_sections(pe_bytes)?
        .into_iter()
        .find(|s| s.name == *b".text\0\0\0")
        .map(|s| PeTextSection {
            virtual_address: s.virtual_address,
            virtual_size: s.virtual_size,
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bytes_no_hits() {
        assert!(find_direct_syscalls(&[], 0).is_empty());
    }

    #[test]
    fn syscall_at_zero() {
        let bytes = [0x0F, 0x05];
        let hits = find_direct_syscalls(&bytes, 0x1000);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, SyscallKind::Syscall);
        assert_eq!(hits[0].offset, 0);
    }

    #[test]
    fn syscall_after_nop() {
        // NOP, syscall, NOP
        let bytes = [0x90, 0x0F, 0x05, 0x90];
        let hits = find_direct_syscalls(&bytes, 0);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, SyscallKind::Syscall);
        assert_eq!(hits[0].offset, 1);
    }

    #[test]
    fn sysenter_detected() {
        let bytes = [0x90, 0x0F, 0x34, 0x90];
        let hits = find_direct_syscalls(&bytes, 0);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, SyscallKind::Sysenter);
    }

    #[test]
    fn int_2e_detected() {
        let bytes = [0x90, 0xCD, 0x2E, 0x90];
        let hits = find_direct_syscalls(&bytes, 0);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, SyscallKind::Int2e);
    }

    #[test]
    fn int_80_not_detected() {
        // int 0x80 is Linux syscall — not our concern
        let bytes = [0x90, 0xCD, 0x80, 0x90];
        let hits = find_direct_syscalls(&bytes, 0);
        assert!(hits.is_empty());
    }

    #[test]
    fn int_3_not_detected() {
        // int3 / CC — debugger break
        let bytes = [0x90, 0xCC, 0x90];
        let hits = find_direct_syscalls(&bytes, 0);
        assert!(hits.is_empty());
    }

    #[test]
    fn mov_with_immediate_containing_syscall_bytes_no_hit() {
        // mov rax, 0x050F  =>  48 C7 C0 0F 05 00 00
        // The 0F 05 here is part of the immediate, not an instruction.
        // iced-x86 decodes this as one MOV instruction, no syscall.
        let bytes = [0x48, 0xC7, 0xC0, 0x0F, 0x05, 0x00, 0x00];
        let hits = find_direct_syscalls(&bytes, 0);
        assert!(hits.is_empty(), "false positive on mov rax, 0x050F: {:?}", hits);
    }

    #[test]
    fn mov_eax_immediate_1295_no_hit() {
        // mov eax, 1295  =>  B8 0F 05 00 00
        let bytes = [0xB8, 0x0F, 0x05, 0x00, 0x00];
        let hits = find_direct_syscalls(&bytes, 0);
        assert!(hits.is_empty(), "false positive on mov eax, 1295: {:?}", hits);
    }

    #[test]
    fn multiple_syscalls() {
        // syscall; nop; syscall; ret
        let bytes = [0x0F, 0x05, 0x90, 0x0F, 0x05, 0xC3];
        let hits = find_direct_syscalls(&bytes, 0);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].offset, 0);
        assert_eq!(hits[1].offset, 3);
    }

    #[test]
    fn syscall_at_end_of_buffer() {
        let mut bytes = vec![0x90u8; 1000];
        bytes.push(0x0F);
        bytes.push(0x05);
        let hits = find_direct_syscalls(&bytes, 0);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, 1000);
    }

    #[test]
    fn truncated_syscall_no_hit() {
        // Just 0F at end — incomplete
        let bytes = [0x90, 0x0F];
        let hits = find_direct_syscalls(&bytes, 0);
        assert!(hits.is_empty());
    }

    #[test]
    fn random_bytes_with_no_syscalls() {
        // Common compiler-generated x86-64: push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret
        let bytes = [0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3];
        let hits = find_direct_syscalls(&bytes, 0);
        assert!(hits.is_empty());
    }

    #[test]
    fn syscall_kind_display() {
        assert_eq!(format!("{}", SyscallKind::Syscall), "syscall");
        assert_eq!(format!("{}", SyscallKind::Sysenter), "sysenter");
        assert_eq!(format!("{}", SyscallKind::Int2e), "int 2eh");
    }

    // ---- PE parser tests ----

    #[test]
    fn pe_garbage_returns_none() {
        let bytes = [0u8; 1024];
        assert!(pe_text_section(&bytes).is_none());
    }

    #[test]
    fn pe_invalid_dos_magic() {
        let mut bytes = vec![0u8; 1024];
        bytes[0] = b'X';
        bytes[1] = b'Y';
        assert!(pe_text_section(&bytes).is_none());
    }

    #[test]
    fn pe_valid_minimal_with_text_section() {
        let mut buf = vec![0u8; 4096];
        // DOS magic
        buf[0] = b'M';
        buf[1] = b'Z';
        // e_lfanew at 0x3C → 0x80
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // NT signature at 0x80
        buf[0x80..0x84].copy_from_slice(&NT_MAGIC.to_le_bytes());
        // COFF header at 0x84 — NumberOfSections (offset +2) = 1
        buf[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        // SizeOfOptionalHeader (offset +16) = 0xF0 (typical for PE32+)
        buf[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        // Section table at 0x84 + 20 + 0xF0 = 0x188
        let section = 0x188;
        buf[section..section + 8].copy_from_slice(b".text\0\0\0");
        // VirtualSize at +8
        buf[section + 8..section + 12].copy_from_slice(&0x1234u32.to_le_bytes());
        // VirtualAddress at +12
        buf[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());

        let parsed = pe_text_section(&buf).unwrap();
        assert_eq!(parsed.virtual_address, 0x1000);
        assert_eq!(parsed.virtual_size, 0x1234);
    }

    #[test]
    fn pe_no_text_section() {
        let mut buf = vec![0u8; 4096];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        buf[0x80..0x84].copy_from_slice(&NT_MAGIC.to_le_bytes());
        buf[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        buf[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        let section = 0x188;
        buf[section..section + 8].copy_from_slice(b".data\0\0\0");
        assert!(pe_text_section(&buf).is_none());
    }

    #[test]
    fn pe_truncated_returns_none() {
        let bytes = [b'M', b'Z'];
        assert!(pe_text_section(&bytes).is_none());
    }

    #[test]
    fn pe_invalid_nt_magic() {
        let mut buf = vec![0u8; 1024];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        buf[0x80..0x84].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        assert!(pe_text_section(&buf).is_none());
    }

    // ---- S06 gap 2: alternate-alignment decode ----

    #[test]
    fn multi_entry_catches_syscall_inside_mov_immediate_alternate_alignment() {
        // mov rax, 0x050F => 48 C7 C0 0F 05 00 00. The offset-0 parse
        // swallows the 0F 05 as the immediate (pinned as no-hit by
        // mov_with_immediate_containing_syscall_bytes_no_hit below), but
        // execution entering at offset 3 executes a REAL syscall. The
        // multi-entry decode entering on those bytes must flag it.
        let bytes = [0x48u8, 0xC7, 0xC0, 0x0F, 0x05, 0x00, 0x00];
        assert!(find_direct_syscalls(&bytes, 0).is_empty());
        let hits = find_direct_syscalls_multi_entry(&bytes, 0);
        assert_eq!(hits.len(), 1, "alternate-alignment entry must be caught: {hits:?}");
        assert_eq!(hits[0].offset, 3);
        assert_eq!(hits[0].kind, SyscallKind::Syscall);
    }

    #[test]
    fn multi_entry_residual_deep_immediate_entry_not_caught() {
        // DOCUMENTED RESIDUAL (see find_direct_syscalls_multi_entry): the
        // same mov-immediate trick placed beyond the bounded entry windows is
        // NOT flagged, even though a jmp directly onto the 0F 05 at offset 19
        // would execute a real syscall. This test pins the limitation so the
        // guarantee cannot silently drift in either direction.
        let mut bytes = vec![0x90u8; 16];
        bytes.extend_from_slice(&[0x48, 0xC7, 0xC0, 0x0F, 0x05, 0x00, 0x00]);
        assert!(find_direct_syscalls(&bytes, 0).is_empty(), "canonical sweep must miss it");
        let hits = find_direct_syscalls_multi_entry(&bytes, 0);
        assert!(hits.is_empty(), "offset 19 is beyond the bounded entry windows — documented residual, got {hits:?}");
    }

    // ---- has_direct_syscall: early-exit twin of the multi-entry Vec ----

    #[test]
    fn has_direct_syscall_agrees_with_multi_entry_vec() {
        // Agreement battery: the predicate must return exactly
        // `!find_direct_syscalls_multi_entry(..).is_empty()` on both the
        // documented hits and the documented misses/residuals.
        let mut long_nop = vec![0x90u8; 4096];
        long_nop.extend_from_slice(&[0x0F, 0x05]);
        let mut deep_immediate = vec![0x90u8; 16];
        deep_immediate.extend_from_slice(&[0x48, 0xC7, 0xC0, 0x0F, 0x05, 0x00, 0x00]);
        let fixtures: &[(&str, Vec<u8>)] = &[
            ("empty", vec![]),
            ("nop sled", vec![0x90; 256]),
            ("syscall at offset 0", vec![0x0F, 0x05]),
            ("syscall near end of long nop buffer", long_nop),
            ("sysenter", vec![0x90, 0x0F, 0x34, 0x90]),
            ("int 2e", vec![0x90, 0xCD, 0x2E, 0x90]),
            ("compiler-typical clean bytes", vec![0x55, 0x48, 0x89, 0xE5, 0x31, 0xC0, 0x5D, 0xC3]),
            ("mov immediate containing syscall bytes", vec![0x48, 0xC7, 0xC0, 0x0F, 0x05, 0x00, 0x00]),
            ("deep-immediate documented residual", deep_immediate.clone()),
            ("int 0x80", vec![0x90, 0xCD, 0x80, 0x90]),
            ("int 3", vec![0x90, 0xCC, 0x90]),
        ];
        for (name, bytes) in fixtures {
            for base in [0u64, 0x1000] {
                assert_eq!(
                    has_direct_syscall(bytes, base),
                    !find_direct_syscalls_multi_entry(bytes, base).is_empty(),
                    "predicate/Vec disagreement on {name:?} at base {base:#x}"
                );
            }
        }
        // Polarity pins beyond mutual agreement: the alternate-alignment
        // mov immediate must HIT, the deep-immediate residual must MISS
        // (both versions agree on the documented S06 residual), int 0x80
        // and int 3 must MISS.
        assert!(has_direct_syscall(&[0x48, 0xC7, 0xC0, 0x0F, 0x05, 0x00, 0x00], 0));
        assert!(!has_direct_syscall(&deep_immediate, 0));
        assert!(!has_direct_syscall(&[0x90, 0xCD, 0x80, 0x90], 0));
        assert!(!has_direct_syscall(&[0x90, 0xCC, 0x90], 0));
    }

    #[test]
    fn has_direct_syscall_still_decodes_alternate_entries_on_longer_buffers() {
        // Buffer LONGER than one entry window (2 * MAX_INSTRUCTION_LEN):
        // the offset-0 sweep swallows the 0F 05 into the mov immediate, so
        // ONLY the alternate-entry decode entering at offset 3 can flag it.
        // Proves the predicate runs the multi-entry passes, not just the
        // canonical sweep.
        let mut bytes = [0x48u8, 0xC7, 0xC0, 0x0F, 0x05, 0x00, 0x00].to_vec();
        bytes.extend_from_slice(&[0x90u8; 2 * MAX_INSTRUCTION_LEN]);
        assert!(bytes.len() > 2 * MAX_INSTRUCTION_LEN);
        assert!(
            find_direct_syscalls(&bytes, 0).is_empty(),
            "pre-condition: offset-0 sweep must miss the immediate"
        );
        assert!(
            has_direct_syscall(&bytes, 0),
            "alternate-entry pass must still run on buffers longer than one window"
        );
        assert_eq!(find_direct_syscalls_multi_entry(&bytes, 0)[0].offset, 3);
    }

    // ---- data-context suppression (in-.text lookup tables) ----

    /// Verbatim bytes from codex.exe `.text` (RVA 0x1000 + 0xd983460..): a
    /// byte lookup table whose linear sweep lands on `0f 05` right after a
    /// run of INVALID decodes. Must not be flagged by any scan entry point.
    const CODEX_TABLE: [u8; 48] = [
        0xb5, 0x3f, 0x98, 0x0d, 0x00, 0x0f, 0x0f, 0x0f, 0x01, 0x0f, 0x0f, 0x0f,
        0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x00, 0x0f, 0x0f,
        0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x02, 0x03, 0x0f, 0x0f, 0x0f, 0x0f,
        0x04, 0x0f, 0x0f, 0x05, 0x0f, 0x0f, 0x0f, 0x06, 0x0f, 0x0f, 0x07, 0x0f,
    ];

    #[test]
    fn syscall_bytes_inside_lookup_table_not_flagged() {
        assert!(find_direct_syscalls(&CODEX_TABLE, 0).is_empty());
        assert!(find_direct_syscalls_multi_entry(&CODEX_TABLE, 0).is_empty());
        assert!(!has_direct_syscall(&CODEX_TABLE, 0));
    }

    #[test]
    fn canonical_syscall_stub_right_after_invalid_is_detected() {
        // 06 = INVALID in 64-bit; mov r10,rcx; mov eax,0x18; syscall; ret.
        let mut bytes = vec![0x90u8; 32];
        bytes.extend_from_slice(&[
            0x06, 0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0, 0, 0, 0x0F, 0x05, 0xC3,
        ]);
        let hits = find_direct_syscalls(&bytes, 0);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].offset, 32 + 1 + 3 + 5);
        assert!(has_direct_syscall(&bytes, 0));
    }

    #[test]
    fn non_stub_syscall_near_invalid_remains_suppressed() {
        // An immediate load followed by syscall lacks the Windows x64
        // argument-register setup and should not override table suppression.
        let mut bytes = vec![0x90u8; 32];
        bytes.extend_from_slice(&[0x06, 0xB8, 0x18, 0, 0, 0, 0x0F, 0x05, 0xC3]);
        assert!(find_direct_syscalls(&bytes, 0).is_empty());
        assert!(!has_direct_syscall(&bytes, 0));
    }

    /// 32 NOPs, `06 90` (one 2-byte INVALID decode), `nops` NOPs, syscall, ret.
    fn invalid_then_syscall(nops: usize) -> Vec<u8> {
        let mut bytes = vec![0x90u8; 32];
        bytes.extend_from_slice(&[0x06, 0x90]);
        bytes.extend(std::iter::repeat(0x90).take(nops));
        bytes.extend_from_slice(&[0x0F, 0x05, 0xC3]);
        bytes
    }

    #[test]
    fn lookback_boundary_after_invalid() {
        let inside = invalid_then_syscall(DATA_CONTEXT_LOOKBACK - 1);
        assert!(find_direct_syscalls(&inside, 0).is_empty());
        assert!(!has_direct_syscall(&inside, 0));

        let beyond = invalid_then_syscall(DATA_CONTEXT_LOOKBACK);
        let hits = find_direct_syscalls(&beyond, 0);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].offset, 34 + DATA_CONTEXT_LOOKBACK);
        assert!(has_direct_syscall(&beyond, 0));
    }

    #[test]
    fn typical_syscall_stub_still_flagged() {
        let mut bytes = vec![0xCCu8; 32];
        bytes.extend_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0, 0, 0, 0x0F, 0x05, 0xC3]);
        assert_eq!(find_direct_syscalls(&bytes, 0).len(), 1);
        assert!(has_direct_syscall(&bytes, 0));
    }

    #[test]
    fn short_buffer_flags_syscall_even_after_invalid() {
        // `06 90` decodes as one INVALID; the syscall follows it directly.
        let bytes = [0x06u8, 0x90, 0x0F, 0x05];
        assert_eq!(find_direct_syscalls(&bytes, 0).len(), 1);
        assert!(has_direct_syscall(&bytes, 0));
    }

    // ---- S06 gap 3: every executable section, not just ".text" ----

    /// Build a minimal PE with the given sections: (name, virtual_size,
    /// virtual_address, characteristics).
    fn build_pe(sections: &[([u8; 8], u32, u32, u32)]) -> Vec<u8> {
        let table = 0x84 + 20 + 0xF0; // 0x188, same layout as the tests above
        let mut buf = vec![0u8; table + sections.len() * 40];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        buf[0x80..0x84].copy_from_slice(&NT_MAGIC.to_le_bytes());
        buf[0x86..0x88].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        buf[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        for (i, (name, vsize, va, chars)) in sections.iter().enumerate() {
            let s = table + i * 40;
            buf[s..s + 8].copy_from_slice(name);
            buf[s + 8..s + 12].copy_from_slice(&vsize.to_le_bytes());
            buf[s + 12..s + 16].copy_from_slice(&va.to_le_bytes());
            buf[s + 36..s + 40].copy_from_slice(&chars.to_le_bytes());
        }
        buf
    }

    #[test]
    fn pe_executable_sections_includes_non_text_exec_section() {
        let buf = build_pe(&[
            (*b".text\0\0\0", 0x1000, 0x1000, IMAGE_SCN_MEM_EXECUTE | 0x4000_0000),
            (*b".fhook\0\0", 0x40, 0x2000, IMAGE_SCN_MEM_EXECUTE | 0x4000_0000),
            (*b".data\0\0\0", 0x80, 0x3000, 0x4000_0000),
        ]);
        let secs = pe_executable_sections(&buf);
        assert_eq!(secs.len(), 2, "both executable sections, not just .text: {secs:?}");
        assert_eq!(secs[0].name, *b".text\0\0\0");
        assert_eq!(secs[1].name, *b".fhook\0\0");
        assert_eq!(secs[1].virtual_address, 0x2000);
        assert_eq!(secs[1].virtual_size, 0x40);
    }

    #[test]
    fn pe_executable_sections_empty_when_nothing_executable() {
        let buf = build_pe(&[(*b".data\0\0\0", 0x80, 0x1000, 0x4000_0000)]);
        assert!(pe_executable_sections(&buf).is_empty());
    }

    #[test]
    fn pe_text_section_ignores_non_text_exec_sections() {
        // Compatibility pin: the .text-only helper still means .text-only.
        let buf = build_pe(&[(*b".rtext\0\0", 0x40, 0x1000, IMAGE_SCN_MEM_EXECUTE | 0x4000_0000)]);
        assert!(pe_text_section(&buf).is_none());
    }
}
