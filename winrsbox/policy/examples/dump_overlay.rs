// Throwaway diagnostic: dump OVERLAY_IDX / WHITEOUTS counts from a live redb.
// Usage: cargo run -p policy --example dump_overlay -- <policy.redb> [substr]
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};

const OVERLAY_IDX: TableDefinition<&str, &str> = TableDefinition::new("overlay_idx");
const WHITEOUTS: TableDefinition<&str, ()> = TableDefinition::new("whiteouts");

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("usage: dump_overlay <redb> [substr]");
    let filter = args.get(2).map(|s| s.to_lowercase());

    let db = Database::open(path).expect("open redb");
    let txn = db.begin_read().expect("read txn");

    let t = txn.open_table(OVERLAY_IDX).expect("open overlay_idx");
    println!("OVERLAY_IDX total entries: {}", t.len().expect("len"));

    if let Some(f) = &filter {
        let mut matched = 0usize;
        let mut samples = Vec::new();
        for e in t.iter().expect("iter").flatten() {
            let (k, v) = e;
            let key = k.value().to_owned();
            if key.contains(f.as_str()) {
                matched += 1;
                if samples.len() < 10 {
                    samples.push(format!("{}  ->  {}", key, v.value()));
                }
            }
        }
        println!("matched '{}': {}", f, matched);
        for s in samples {
            println!("  {s}");
        }
    }

    if let Ok(w) = txn.open_table(WHITEOUTS) {
        println!("WHITEOUTS total entries: {}", w.len().expect("len"));
    }

    // Exact-membership probes: does the DIRECTORY key itself exist in OVERLAY_IDX,
    // not just its children? This is what read-through redirect (exact get) needs.
    let probes = [
        r"c:\users\computer\appdata\local\hermes\hermes-agent",
        r"c:\users\computer\appdata\local\hermes\hermes-agent\.git",
        r"c:\users\computer\appdata\local\hermes\hermes-agent\.git\head",
        r"c:\users\computer\appdata\local\hermes\hermes-agent\.git\hooks",
        r"c:\users\computer\appdata\local\hermes\hermes-agent\agent",
        r"c:\users\computer\appdata\local\hermes\hermes-agent\readme.md",
    ];
    println!("--- exact OVERLAY_IDX membership ---");
    for p in probes {
        let present = t.get(p).ok().flatten().is_some();
        println!("  [{}] {}", if present { "HIT " } else { "MISS" }, p);
    }
}
