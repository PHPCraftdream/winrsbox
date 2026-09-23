use super::*;
use crate::hooks::overlay::{cow_copy_verified, discard_torn_materialization};

    // ── C04 (docs/review-xa-2026-09-20): materialization torn-file & race
    // discipline ───────────────────────────────────────────────────────────
    //
    // The overlay materialization race is decided solely by the atomic
    // create_new(true) gate: the AlreadyExists loser never opens or writes
    // the destination, so content can never be clobbered or interleaved.
    // These tests pin that end-to-end under real thread contention, and pin
    // the C04 torn-file rule: a copy/write that fails after the exclusive
    // create must not leave a short file behind — every later
    // exists()/create_new call would treat the torn file as fully
    // materialized forever. No sleeps: each round uses a FRESH destination
    // path and joins all racers before asserting, so the asserts are
    // deterministic.

    /// Distinct payloads: 64 KiB each, one distinct fill byte per source
    /// (0xA0..0xD0) so a torn, interleaved or truncated result cannot be
    /// mistaken for any single source payload.
    const C04_PAYLOAD_LEN: usize = 64 * 1024;

    fn c04_payload(i: usize) -> Vec<u8> {
        vec![0xA0 + (i as u8) * 0x10; C04_PAYLOAD_LEN]
    }

    /// Assert `content` is byte-identical to EXACTLY ONE of `payloads`
    /// (complete length — no interleaving, no truncation).
    fn c04_assert_exactly_one_payload(content: &[u8], payloads: &[Vec<u8>]) {
        assert_eq!(
            content.len(),
            payloads[0].len(),
            "materialized content must be complete length, got {} bytes",
            content.len()
        );
        let winners: Vec<usize> = payloads
            .iter()
            .enumerate()
            .filter(|(_, p)| p.as_slice() == content)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            winners.len(),
            1,
            "content must be byte-identical to exactly one payload, matched {winners:?}"
        );
    }

    /// C04: 4 threads race `prepare_overlay_in_roots` on the SAME
    /// destination, each with its own verified CoW source. All calls return
    /// Some; the final content must be byte-identical to EXACTLY ONE of the
    /// four source payloads — the atomic create_new(true) gate means the
    /// loser never opens the destination, so no clobbering, interleaving or
    /// truncation can occur. Repeated over rounds, each with a fresh
    /// destination, to actually hit the race window.
    #[test]
    fn c04_concurrent_cow_materialization_single_winner() {
        let dir = unique_temp_path("c04-cow-race");
        std::fs::create_dir_all(&dir).expect("create base dir");
        let root_str = dir.to_string_lossy().to_ascii_lowercase();
        let roots = [root_str.as_str()];

        let payloads: Vec<Vec<u8>> = (0..4).map(c04_payload).collect();
        let sources: Vec<PathBuf> = (0..4)
            .map(|i| dir.join(format!("c04-src-{i}.bin")))
            .collect();
        for (src, payload) in sources.iter().zip(payloads.iter()) {
            std::fs::write(src, payload).expect("write distinct CoW source");
        }

        for round in 0..4u32 {
            // FRESH destination per round — a settled file can no longer
            // race (exists() fast path short-circuits every racer).
            let dest = dir.join(format!("c04-cow-dest-round-{round}.bin"));
            std::thread::scope(|s| {
                for src in &sources {
                    let dest = dest.clone();
                    let d = Decision {
                        mode: Mode::Cow,
                        overlay: Some(dest),
                        cow_from: Some(src.clone()),
                        mock_payload: None,
                    };
                    s.spawn(move || {
                        assert!(
                            prepare_overlay_in_roots(&d, &roots).is_some(),
                            "every racer must get Some (a skipped copy is never a hard failure)"
                        );
                    });
                }
            });

            let content = std::fs::read(&dest)
                .expect("destination must exist after concurrent materialization");
            c04_assert_exactly_one_payload(&content, &payloads);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// C04: same single-winner discipline for mock materialization — 4
    /// threads race `materialize_mock_overlay_in_roots` on the SAME
    /// destination with 4 distinct payloads; the final content must equal
    /// exactly one payload exactly.
    #[test]
    fn c04_concurrent_mock_materialization_single_winner() {
        let dir = unique_temp_path("c04-mock-race");
        std::fs::create_dir_all(&dir).expect("create base dir");
        let root_str = dir.to_string_lossy().to_ascii_lowercase();
        let roots = [root_str.as_str()];

        // Distinct payloads (fill bytes 0xA0..0xD0); small is fine — this
        // is a race-window test, not a load test.
        let payloads: Vec<Vec<u8>> = (0..4)
            .map(|i| vec![0xA0 + (i as u8) * 0x10; 16 * 1024])
            .collect();

        for round in 0..4u32 {
            let dest = dir.join(format!("c04-mock-dest-round-{round}.bin"));
            std::thread::scope(|s| {
                for payload in &payloads {
                    let dest = dest.clone();
                    s.spawn(move || {
                        materialize_mock_overlay_in_roots(&dest, payload, &roots);
                    });
                }
            });

            let content = std::fs::read(&dest)
                .expect("destination must exist after concurrent materialization");
            c04_assert_exactly_one_payload(&content, &payloads);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// C04 pin: `cow_copy_verified` with an unopenable source returns false
    /// AND leaves no destination file — skip-on-failure semantics (the copy
    /// is best-effort, and a half-made destination must not linger as a
    /// poisoned overlay entry).
    #[test]
    fn c04_failed_copy_leaves_no_destination() {
        let dir = unique_temp_path("c04-cow-fail");
        std::fs::create_dir_all(&dir).expect("create base dir");
        let dest = dir.join("c04-never-materialized.bin");
        let missing_src = dir.join("c04-no-such-source.bin");

        assert!(
            !cow_copy_verified(&missing_src, &dest),
            "an unopenable source must skip the copy (false)"
        );
        assert!(
            !dest.exists(),
            "a failed copy must leave NO destination file behind"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// C04 pin: the torn-materialization helper removes the file outright,
    /// so the next open re-races the materialization from a clean slate.
    #[test]
    fn c04_discard_torn_materialization_removes_file() {
        let dir = unique_temp_path("c04-discard");
        std::fs::create_dir_all(&dir).expect("create base dir");
        let torn = dir.join("c04-torn.bin");
        std::fs::write(&torn, b"partial bytes from a failed copy").expect("seed torn file");
        assert!(torn.exists(), "premise: the torn file exists");

        discard_torn_materialization(&torn);
        assert!(!torn.exists(), "the torn file must be gone after discard");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// C04 pin: a pre-materialized mock payload is untouched by a later
    /// (loser/late-comer) call with a different payload — the AlreadyExists
    /// loser never opens the destination, so the first content stands.
    #[test]
    fn c04_mock_payload_untouched_by_loser() {
        let dir = unique_temp_path("c04-mock-loser");
        std::fs::create_dir_all(&dir).expect("create base dir");
        let root_str = dir.to_string_lossy().to_ascii_lowercase();
        let roots = [root_str.as_str()];
        let overlay = dir.join("c04-payload.bin");
        let payload_a: &[u8] = b"payload-A-first-winner";
        let payload_b: &[u8] = b"payload-B-loser-must-not-land";

        materialize_mock_overlay_in_roots(&overlay, payload_a, &roots);
        assert_eq!(
            std::fs::read(&overlay).expect("read after winner"),
            payload_a,
            "winner's payload A must be materialized"
        );

        materialize_mock_overlay_in_roots(&overlay, payload_b, &roots);
        assert_eq!(
            std::fs::read(&overlay).expect("read after loser"),
            payload_a,
            "loser/late-comer with payload B must NOT overwrite payload A"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
