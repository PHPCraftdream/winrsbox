//! Memory-guard level shared by the launcher (author) and hook.dll (consumer):
//! the enum, its canonical wire/log spelling, and its loose CLI/env parser.

use serde::{Deserialize, Serialize};

/// Memory-guard level, authored by the launcher and consumed by hook.dll.
/// Replaces the ad-hoc `guard: String`, which was compared case-insensitively
/// at one gate and case-sensitively at another (review XA 2026-09-20, S02).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuardLevel { #[default] None, Scan, Full, Static }

/// The Display form is THE canonical wire/log spelling (lowercase).
impl std::fmt::Display for GuardLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::None => "none", Self::Scan => "scan",
            Self::Full => "full", Self::Static => "static",
        })
    }
}

impl GuardLevel {
    /// Trim + ASCII-case-insensitive match against the lowercase spellings;
    /// anything else is rejected. Accepts loose human spellings from CLI/env
    /// authors — but always re-emit via Display, never echo the input.
    pub fn parse_loose(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "none" => Some(Self::None), "scan" => Some(Self::Scan),
            "full" => Some(Self::Full), "static" => Some(Self::Static),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_level_parse_loose_is_case_insensitive() {
        for (s, want) in [
            ("full", Some(GuardLevel::Full)), ("STATIC", Some(GuardLevel::Static)),
            (" Static ", Some(GuardLevel::Static)), ("Scan", Some(GuardLevel::Scan)),
            ("none", Some(GuardLevel::None)), ("jit", None), ("", None),
        ] {
            assert_eq!(GuardLevel::parse_loose(s), want, "parse_loose({s:?})");
        }
    }

    #[test]
    fn guard_level_display_is_canonical_lowercase() {
        for (g, s) in [
            (GuardLevel::None, "none"), (GuardLevel::Scan, "scan"),
            (GuardLevel::Full, "full"), (GuardLevel::Static, "static"),
        ] {
            assert_eq!(g.to_string(), s);
        }
    }
}
