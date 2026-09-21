// Code integrity scanner — detects direct syscall instructions in PE images.
//
// Uses iced-x86 for accurate x86-64 instruction decoding (avoids false positives
// from byte patterns like 0F 05 appearing as immediate operands).
//
// Crate version assumed:
//   iced-x86 = "1"  (no_std + decoder, no encoder)

use iced_x86::{Decoder, DecoderOptions, Mnemonic};
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

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

/// Disassemble `bytes` as x86-64 instructions starting at `base_addr` and
/// return all direct syscall instructions found.
///
/// This is *linear sweep* disassembly — it decodes from byte 0 sequentially.
/// Real .text sections may have padding/data between functions, but iced-x86
/// handles invalid instructions by returning a 1-byte INVALID instruction
/// and continuing. False positives are rare because immediate operand bytes
/// matching 0F 05 / 0F 34 / CD 2E only become "instructions" if linear sweep
/// happens to land on them as instruction boundaries — which is statistically
/// rare in compiler-generated code.
pub fn find_direct_syscalls(bytes: &[u8], base_addr: u64) -> Vec<SyscallHit> {
    let mut hits = Vec::new();
    let mut decoder = Decoder::with_ip(64, bytes, base_addr, DecoderOptions::NONE);
    while decoder.can_decode() {
        let pos = decoder.position();
        let instr = decoder.decode();
        let kind = match instr.mnemonic() {
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
        };
        if let Some(k) = kind {
            hits.push(SyscallHit { offset: pos, kind: k });
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// PE parser — find .text section
// ---------------------------------------------------------------------------

const DOS_MAGIC: u16 = 0x5A4D; // "MZ"
const NT_MAGIC: u32 = 0x00004550; // "PE\0\0"

fn read_u16_le(buf: &[u8], offset: usize) -> Option<u16> {
    buf.get(offset..offset + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn read_u32_le(buf: &[u8], offset: usize) -> Option<u32> {
    buf.get(offset..offset + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Parse a buffer containing the PE headers (DOS + NT + sections) and return
/// the `.text` section's RVA and virtual size.
///
/// Buffer must contain at least the DOS header, NT headers, and section table.
/// Typically 4 KiB from the image base is enough.
pub fn pe_text_section(pe_bytes: &[u8]) -> Option<PeTextSection> {
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

    for i in 0..num_sections {
        let s = section_table + i * SECTION_HEADER_SIZE;
        let name_bytes = pe_bytes.get(s..s + 8)?;
        // Compare against ".text\0\0\0"
        if name_bytes == b".text\0\0\0" {
            let virtual_size = read_u32_le(pe_bytes, s + 8)?;
            let virtual_address = read_u32_le(pe_bytes, s + 12)?;
            return Some(PeTextSection { virtual_address, virtual_size });
        }
    }
    None
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
}
