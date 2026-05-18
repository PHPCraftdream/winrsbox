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

criterion_group!(
    benches,
    bench_cache_hit,
    bench_cache_miss_passthrough,
    bench_cache_miss_deny,
    bench_cache_key_length,
);
criterion_main!(benches);
