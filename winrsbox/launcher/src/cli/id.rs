use xxhash_rust::xxh3::Xxh3;

/// Generate a deterministic ID: `<kind>-<8hex>` from xxh3 of sorted args.
pub fn generate_id(kind: &str, args: &[&str]) -> String {
    let mut parts: Vec<&str> = args.to_vec();
    parts.sort();
    let mut hasher = Xxh3::new();
    for p in &parts {
        hasher.update(p.as_bytes());
        hasher.update(&[0]);
    }
    let hash = hasher.digest();
    format!("{}-{:08x}", kind, hash & 0xFFFFFFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_deterministic() {
        let a = generate_id("rule", &["c:\\users\\*", "deny"]);
        let b = generate_id("rule", &["c:\\users\\*", "deny"]);
        assert_eq!(a, b);
    }

    #[test]
    fn id_ignores_order() {
        let a = generate_id("rule", &["c:\\test", "cow"]);
        let b = generate_id("rule", &["cow", "c:\\test"]);
        assert_eq!(a, b);
    }

    #[test]
    fn id_kind_differs() {
        let a = generate_id("rule", &["c:\\test"]);
        let b = generate_id("mock", &["c:\\test"]);
        assert_ne!(a, b);
    }

    #[test]
    fn id_format() {
        let id = generate_id("rule", &["c:\\test"]);
        assert!(id.starts_with("rule-"));
        assert_eq!(id.len(), 13); // "rule-" + 8 hex chars
    }

    #[test]
    fn id_case_sensitive_args() {
        let a = generate_id("rule", &["c:\\test"]);
        let b = generate_id("rule", &["c:\\TEST"]);
        assert_ne!(a, b);
    }
}
