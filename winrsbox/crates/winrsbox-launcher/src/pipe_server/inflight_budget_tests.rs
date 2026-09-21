    use super::*;

    /// The audit invariant: per-message size x handler concurrency is no
    /// longer the memory bound. MAX_INFLIGHT_MSG_BYTES is, and it must
    /// bind strictly below the old uncapped 128 x 16 MiB = 2 GiB product.
    #[test]
    fn inflight_cap_binds_below_the_uncapped_product() {
        let old_product = MAX_CONCURRENT_HANDLERS * ipc::MAX_MSG_LEN;
        assert_eq!(old_product, 128 * 16 * 1024 * 1024);
        assert!(
            MAX_INFLIGHT_MSG_BYTES < old_product,
            "in-flight cap {MAX_INFLIGHT_MSG_BYTES} must bind below the old {old_product}-byte product"
        );
    }

    /// The budget admits 4 maximal (16 MiB) messages and nothing more; a
    /// released reservation frees exactly its bytes.
    #[test]
    fn budget_caps_total_inflight_bytes() {
        let b = ByteBudget::new(MAX_INFLIGHT_MSG_BYTES);
        let msg = ipc::MAX_MSG_LEN;
        let r1 = b.try_reserve(msg);
        let r2 = b.try_reserve(msg);
        let r3 = b.try_reserve(msg);
        let r4 = b.try_reserve(msg);
        assert!(r1.is_some() && r2.is_some() && r3.is_some() && r4.is_some());
        assert!(b.try_reserve(1).is_none(), "5th maximal message must be refused");
        drop(r4);
        assert!(b.try_reserve(1).is_some(), "released bytes must be reusable");
    }

    /// A starved reservation times out instead of blocking forever, and
    /// succeeds promptly once budget is released (no permanent wedge).
    #[test]
    fn budget_times_out_when_starved_then_recovers() {
        let b = ByteBudget::new(100);
        let r = b.try_reserve(100).unwrap();
        assert!(b.reserve_timeout(10, Duration::from_millis(50)).is_none());
        drop(r);
        let r2 = b.reserve_timeout(10, Duration::from_secs(2));
        assert!(r2.is_some(), "post-release reservation must succeed");
    }

    /// A single declared size larger than the whole budget is clamped to
    /// it (bounded), not rejected: one legal-but-huge message still flows.
    #[test]
    fn oversize_request_is_clamped_to_budget() {
        let b = ByteBudget::new(1000);
        let r = b.reserve_timeout(5000, Duration::from_millis(10));
        assert!(r.is_some(), "single oversize request is clamped, not refused");
        assert!(b.try_reserve(1).is_none(), "clamped request must consume the whole budget");
    }

    /// PrefixedReader replays the already-read length prefix, then serves
    /// the body from the pipe, so ipc::read_msg parses both untouched.
    #[test]
    fn prefixed_reader_serves_prefix_then_delegates() {
        use std::io::Cursor;
        let mut inner = Cursor::new(b"BODY".to_vec());
        let mut pr = PrefixedReader { prefix: 7u32.to_le_bytes(), pos: 0, inner: &mut inner };
        let mut out = Vec::new();
        pr.read_to_end(&mut out).unwrap();
        let mut want = 7u32.to_le_bytes().to_vec();
        want.extend_from_slice(b"BODY");
        assert_eq!(out, want);
        // inner was left untouched after its bytes were consumed
        assert_eq!(inner.position(), 4);
    }
