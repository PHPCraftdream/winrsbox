use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use policy::Policy;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

fn make_policy() -> (tempfile::TempDir, Policy) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("policy.redb");
    let sandbox = dir.path().join("sb");
    let mock_dirs = dir.path().join("md");
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&sandbox).unwrap();
    std::fs::create_dir_all(&mock_dirs).unwrap();
    std::fs::create_dir_all(&project).unwrap();

    let p = Policy::open_or_create(
        &db_path,
        sandbox,
        mock_dirs,
        project,
    ).unwrap();

    (dir, p)
}

fn make_policy_with_deny() -> (tempfile::TempDir, Policy) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("policy.redb");
    let sandbox = dir.path().join("sb");
    let mock_dirs = dir.path().join("md");
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&sandbox).unwrap();
    std::fs::create_dir_all(&mock_dirs).unwrap();
    std::fs::create_dir_all(&project).unwrap();

    let p = Policy::open_or_create(
        &db_path,
        sandbox,
        mock_dirs,
        project,
    ).unwrap();

    let cfg_path = dir.path().join("config.ktv");
    let mut f = std::fs::File::create(&cfg_path).unwrap();
    write!(f, "defaults: {{\n\
        \x20   read: passthrough\n\
        \x20   write: cow\n\
        }}\n\
        \n\
        rules: [\n\
        \x20   {{\n\
        \x20       prefix: c:\\\\bench\n\
        \x20       write: deny\n\
        \x20   }}\n\
        ]").unwrap();
    drop(f);
    p.load_config(&cfg_path).unwrap();

    (dir, p)
}

fn bench_cache_hit(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_decide");
    let (_dir, policy) = make_policy();
    let path = r"c:\users\alice\appdata\local\programs\app\app.exe";
    policy.decide(path, false);

    group.bench_function("cache_hit", |b| {
        b.iter(|| policy.decide(black_box(path), false))
    });
    group.finish();
}

fn bench_cache_miss_passthrough(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_decide");
    let (_dir, policy) = make_policy();
    let counter = AtomicU64::new(0);

    group.bench_function("cache_miss_passthrough", |b| {
        b.iter_batched(
            || {
                let i = counter.fetch_add(1, Ordering::Relaxed);
                format!("c:\\bench\\{}", i)
            },
            |path| policy.decide(black_box(&path), false),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_cache_miss_deny(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_decide");
    let (_dir, policy) = make_policy_with_deny();
    let counter = AtomicU64::new(0);

    group.bench_function("cache_miss_deny", |b| {
        b.iter_batched(
            || {
                let i = counter.fetch_add(1, Ordering::Relaxed);
                format!("c:\\bench\\{}", i)
            },
            |path| policy.decide(black_box(&path), true),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_cache_key_length(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_decide");
    let (_dir, policy) = make_policy();
    let long: String = "c:\\".to_string() + &"subdir\\".repeat(24) + "file.exe";

    group.bench_function("cache_key_short", |b| {
        b.iter(|| policy.decide(black_box("c:\\a"), false))
    });

    policy.decide(&long, false);
    group.bench_function("cache_key_long_200b", |b| {
        b.iter(|| policy.decide(black_box(&long), false))
    });
    group.finish();
}

fn bench_cache_miss_with_depth(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_decide");
    let (_dir, policy) = make_policy();
    let counter = AtomicU64::new(0);

    group.bench_function("cache_miss_with_depth", |b| {
        b.iter_batched(
            || {
                let i = counter.fetch_add(1, Ordering::Relaxed);
                format!("c:\\bench\\{}", i)
            },
            |path| policy.decide_with_context(black_box(&path), false, Some(2), None),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_cache_miss_with_exe(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_decide");
    let (_dir, policy) = make_policy();
    let counter = AtomicU64::new(0);

    group.bench_function("cache_miss_with_exe", |b| {
        b.iter_batched(
            || {
                let i = counter.fetch_add(1, Ordering::Relaxed);
                format!("c:\\bench\\{}", i)
            },
            |path| policy.decide_with_context(
                black_box(&path), false, None, Some("c:\\app\\target.exe"),
            ),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_cache_miss_with_both(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_decide");
    let (_dir, policy) = make_policy();
    let counter = AtomicU64::new(0);

    group.bench_function("cache_miss_with_both", |b| {
        b.iter_batched(
            || {
                let i = counter.fetch_add(1, Ordering::Relaxed);
                format!("c:\\bench\\{}", i)
            },
            |path| policy.decide_with_context(
                black_box(&path), false, Some(3), Some("c:\\bin\\app.exe"),
            ),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_cache_key_composite(c: &mut Criterion) {
    use xxhash_rust::xxh3::Xxh3;

    fn cache_key(path: &str, write: bool, depth: Option<u8>, exe_lower: Option<&str>) -> u128 {
        let mut h1 = Xxh3::new();
        h1.update(path.as_bytes());
        h1.update(&[if write { 1u8 } else { 0u8 }]);
        let path_hash = h1.digest();

        let mut h2 = Xxh3::new();
        if let Some(d) = depth {
            h2.update(&[1, d]);
        } else {
            h2.update(&[0]);
        }
        if let Some(e) = exe_lower {
            h2.update(&[1]);
            h2.update(e.as_bytes());
        } else {
            h2.update(&[0]);
        }
        let ctx_hash = h2.digest();

        ((path_hash as u128) << 64) | (ctx_hash as u128)
    }

    let mut group = c.benchmark_group("policy_decide");

    group.bench_function("cache_key_composite_none", |b| {
        b.iter(|| cache_key(black_box(r"c:\users\alice\foo.txt"), black_box(false), black_box(None), black_box(None)))
    });

    group.bench_function("cache_key_composite_both", |b| {
        b.iter(|| cache_key(black_box(r"c:\users\alice\foo.txt"), black_box(true), black_box(Some(3)), black_box(Some(r"c:\bin\app.exe"))))
    });

    group.bench_function("cache_key_composite_short", |b| {
        b.iter(|| cache_key(black_box("c:\\a"), black_box(false), black_box(Some(0)), black_box(Some("x.exe"))))
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_cache_hit,
    bench_cache_miss_passthrough,
    bench_cache_miss_deny,
    bench_cache_key_length,
    bench_cache_miss_with_depth,
    bench_cache_miss_with_exe,
    bench_cache_miss_with_both,
    bench_cache_key_composite,
);
criterion_main!(benches);
