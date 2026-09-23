use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use winrsbox_policy::reg;
use std::time::Duration;
use std::sync::atomic::{AtomicU64, Ordering};

fn bench_nt_to_friendly(c: &mut Criterion) {
    let mut group = c.benchmark_group("reg");
    let raw_hklm: Vec<u16> = r"\Registry\Machine\Software\Microsoft\Windows".encode_utf16().collect();
    let raw_hkcu: Vec<u16> = r"\Registry\User\S-1-5-21-123-500\Software\App".encode_utf16().collect();

    group.bench_function("nt_to_friendly_hklm", |b| {
        b.iter(|| reg::nt_to_friendly(black_box(&raw_hklm)))
    });
    group.bench_function("nt_to_friendly_hkcu", |b| {
        b.iter(|| reg::nt_to_friendly(black_box(&raw_hkcu)))
    });
    group.finish();
}

fn bench_values_json(c: &mut Criterion) {
    let mut group = c.benchmark_group("reg");

    let mut small = rustc_hash::FxHashMap::default();
    small.insert("name".into(), reg::RegEntry::Value(reg::RegValue {
        typ: reg::RegType::Sz, data: reg::RegData::String("ProductName".into()),
    }));
    small.insert("build".into(), reg::RegEntry::Value(reg::RegValue {
        typ: reg::RegType::Dword, data: reg::RegData::U32(22631),
    }));
    small.insert("guid".into(), reg::RegEntry::Value(reg::RegValue {
        typ: reg::RegType::Sz, data: reg::RegData::String("00000000-0000-0000-0000-000000000000".into()),
    }));

    let small_json = reg::serialize_values_json(&small);

    group.bench_function("values_json_serialize_3", |b| {
        b.iter(|| reg::serialize_values_json(black_box(&small)))
    });
    group.bench_function("values_json_parse_3", |b| {
        b.iter(|| reg::parse_values_json(black_box(&small_json)))
    });

    let mut large = rustc_hash::FxHashMap::default();
    for i in 0..100 {
        large.insert(format!("value_{i}"), reg::RegEntry::Value(reg::RegValue {
            typ: reg::RegType::Sz, data: reg::RegData::String(format!("data_{i}")),
        }));
    }
    let large_json = reg::serialize_values_json(&large);

    group.bench_function("values_json_serialize_100", |b| {
        b.iter(|| reg::serialize_values_json(black_box(&large)))
    });
    group.bench_function("values_json_parse_100", |b| {
        b.iter(|| reg::parse_values_json(black_box(&large_json)))
    });

    group.finish();
}

fn bench_reg_decide(c: &mut Criterion) {
    let mut group = c.benchmark_group("reg_decide");
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("policy.redb");
    let workreg = dir.path().join("workreg");
    std::fs::create_dir_all(&workreg).unwrap();
    let rdb = redb::Database::create(&db_path).unwrap();
    { let txn = rdb.begin_write().unwrap(); txn.open_table(winrsbox_policy::db::REG_RULES).unwrap(); txn.open_table(winrsbox_policy::db::REG_MOCKS).unwrap(); txn.commit().unwrap(); }
    let db = std::sync::Arc::new(rdb);
    let rp = winrsbox_policy::RegistryPolicy::open(db, workreg).unwrap();

    rp.decide(r"hklm\software\foo", Some("bar"), false);

    group.bench_function("cache_hit", |b| {
        b.iter(|| rp.decide(black_box(r"hklm\software\foo"), black_box(Some("bar")), false))
    });

    let counter = AtomicU64::new(0);
    group.bench_function("cache_miss", |b| {
        b.iter_batched(
            || {
                let i = counter.fetch_add(1, Ordering::Relaxed);
                format!(r"hklm\software\bench\key{i}")
            },
            |path| rp.decide(black_box(&path), black_box(Some("val")), false),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_overlay_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("reg_overlay");
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("workreg");
    std::fs::create_dir_all(&root).unwrap();
    let mut ov = winrsbox_policy::reg_overlay::RegOverlay::new(root.clone());

    group.bench_function("set_single", |b| {
        let counter = AtomicU64::new(0);
        b.iter(|| {
            let i = counter.fetch_add(1, Ordering::Relaxed);
            ov.set(
                &format!("hklm\\bench\\key{i}"), "val",
                winrsbox_policy::reg::RegValue { typ: winrsbox_policy::reg::RegType::Dword, data: winrsbox_policy::reg::RegData::U32(i as u32) },
            ).unwrap();
        })
    });

    group.bench_function("get_hit", |b| {
        ov.set("hklm\\bench\\static", "val",
            winrsbox_policy::reg::RegValue { typ: winrsbox_policy::reg::RegType::Dword, data: winrsbox_policy::reg::RegData::U32(1) },
        ).unwrap();
        b.iter(|| ov.get(black_box("hklm\\bench\\static"), black_box("val")))
    });

    group.bench_function("get_miss", |b| {
        b.iter(|| ov.get(black_box("hklm\\nonexistent"), black_box("val")))
    });

    group.finish();

    let mut group2 = c.benchmark_group("reg_overlay");
    for n in [10, 100] {
        let dir2 = tempfile::tempdir().unwrap();
        let root2 = dir2.path().join("workreg");
        std::fs::create_dir_all(&root2).unwrap();
        let mut ov2 = winrsbox_policy::reg_overlay::RegOverlay::new(root2.clone());
        for i in 0..n {
            ov2.set(
                &format!("hklm\\bench\\key{i}"), &format!("val{i}"),
                winrsbox_policy::reg::RegValue { typ: winrsbox_policy::reg::RegType::Sz, data: winrsbox_policy::reg::RegData::String(format!("data{i}")) },
            ).unwrap();
        }
        drop(ov2);
        group2.bench_function(format!("load_from_disk_n={n}"), |b| {
            b.iter(|| winrsbox_policy::reg_overlay::RegOverlay::load_from_disk(black_box(root2.clone())).unwrap())
        });
    }
    group2.finish();
}

fn bench_reg_decide_scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("reg_decide");
    for n in [10, 50] {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("policy.redb");
        let workreg = dir.path().join("workreg");
        std::fs::create_dir_all(&workreg).unwrap();
        let rdb = redb::Database::create(&db_path).unwrap();
        { let txn = rdb.begin_write().unwrap(); txn.open_table(winrsbox_policy::db::REG_RULES).unwrap(); txn.open_table(winrsbox_policy::db::REG_MOCKS).unwrap(); txn.commit().unwrap(); }
        let db = std::sync::Arc::new(rdb);
        for i in 0..n {
            winrsbox_policy::db::reg_rule_upsert(&db, &winrsbox_policy::db::RuleRow {
                id: format!("r{i}"), prefix: format!("hklm\\rule{i:04}"),
                mode_read: winrsbox_policy::db::RuleMode::Passthrough, mode_write: winrsbox_policy::db::RuleMode::Deny,
                when: None,
            }).unwrap();
        }
        let rp = winrsbox_policy::RegistryPolicy::open(db, workreg).unwrap();
        let counter = AtomicU64::new(0);
        group.bench_function(format!("cache_miss_n={n}"), |b| {
            b.iter_batched(
                || { let i = counter.fetch_add(1, Ordering::Relaxed); format!("hklm\\rule{:04}\\sub{i}", i % (n as u64)) },
                |path| rp.decide(black_box(&path), None, true),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_overlay_many_keys(c: &mut Criterion) {
    // Perf-finding workload: writes to many INDEPENDENT keys. Before the
    // per-key restructure every set() prefix-scanned all values accumulated
    // so far (O(T) per write, O(T²) per batch); after, each write touches
    // only its own key's values. Disk I/O (tmp+rename per set) is included
    // on purpose — this is the end-to-end number.
    let mut group = c.benchmark_group("reg_overlay_many_keys");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));
    for n in [100, 400] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("workreg");
        std::fs::create_dir_all(&root).unwrap();
        group.bench_function(format!("independent_key_writes_n={n}"), |b| {
            b.iter_batched(
                || winrsbox_policy::reg_overlay::RegOverlay::new(root.clone()),
                |mut ov| {
                    for i in 0..n {
                        ov.set(
                            &format!("hklm\\bulk\\key{i}"), "val",
                            winrsbox_policy::reg::RegValue {
                                typ: winrsbox_policy::reg::RegType::Dword,
                                data: winrsbox_policy::reg::RegData::U32(i as u32),
                            },
                        ).unwrap();
                    }
                },
                BatchSize::PerIteration,
            )
        });
    }
    group.finish();
}

fn bench_overlay_read_scale(c: &mut Criterion) {
    // In-memory read cost at scale (no disk in the timed section): with T
    // values across T distinct keys, the old flat-map enumerate was O(T) per
    // key touched; the per-key map is O(Vk). get() no longer allocates a
    // composite key string.
    let mut group = c.benchmark_group("reg_overlay_read_scale");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(3));
    for t in [1_000usize, 5_000] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("workreg");
        std::fs::create_dir_all(&root).unwrap();
        let mut ov = winrsbox_policy::reg_overlay::RegOverlay::new(root.clone());
        for i in 0..t {
            ov.set(
                &format!("hklm\\scale\\key{i}"), "val",
                winrsbox_policy::reg::RegValue {
                    typ: winrsbox_policy::reg::RegType::Dword,
                    data: winrsbox_policy::reg::RegData::U32(i as u32),
                },
            ).unwrap();
        }
        let keys: Vec<String> = (0..t).map(|i| format!("hklm\\scale\\key{i}")).collect();
        group.bench_function(format!("enumerate_all_keys_t={t}"), |b| {
            b.iter(|| {
                for k in &keys {
                    black_box(ov.enumerate_overlay_values(black_box(k)));
                }
            })
        });
        group.bench_function(format!("get_each_key_t={t}"), |b| {
            b.iter(|| {
                for k in &keys {
                    black_box(ov.get(black_box(k), black_box("val")));
                }
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_nt_to_friendly, bench_values_json, bench_reg_decide, bench_overlay_ops, bench_reg_decide_scale, bench_overlay_many_keys, bench_overlay_read_scale);
criterion_main!(benches);
