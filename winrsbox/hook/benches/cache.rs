use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use hook::cache::HookCache;
use policy::{Decision, Mode};

const LOWER: &str = "c:\\users\\alice\\appdata\\local\\programs\\app\\app.exe";
const MIXED_CASE: &str = "C:\\Users\\Alice\\AppData\\Local\\Programs\\App\\APP.EXE";

fn passthrough() -> Decision {
    Decision { mode: Mode::Passthrough, overlay: None, cow_from: None, mock_payload: None }
}

fn bench_get_caseless_hit(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache");
    let cache = HookCache::new();
    cache.insert(LOWER, false, passthrough());

    group.bench_function("get_caseless_hit", |b| {
        b.iter(|| cache.get_caseless(black_box(MIXED_CASE), false))
    });
    group.finish();
}

fn bench_get_caseless_miss(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache");
    let cache = HookCache::new();
    cache.insert(LOWER, false, passthrough());

    group.bench_function("get_caseless_miss", |b| {
        b.iter(|| cache.get_caseless(black_box("c:\\nonexistent\\xyz"), false))
    });
    group.finish();
}

fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache");
    let decision = passthrough();

    group.bench_function("insert", |b| {
        let cache = HookCache::new();
        b.iter(|| {
            cache.insert(black_box(LOWER), false, decision.clone());
        })
    });
    group.finish();
}

fn bench_invalidate(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache");
    let decision = passthrough();

    group.bench_function("invalidate", |b| {
        b.iter_batched(
            || {
                let cache = HookCache::new();
                cache.insert(LOWER, false, decision.clone());
                cache.insert(LOWER, true, decision.clone());
                cache
            },
            |cache| cache.invalidate(black_box(LOWER)),
            BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_get_caseless_short_vs_long(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache");
    let short = "c:\\a\\b.txt";
    let long: String = "c:\\".to_string() + &"subdir\\".repeat(24) + "file.exe";

    let cache = HookCache::new();
    cache.insert(short, false, passthrough());
    cache.insert(&long, false, passthrough());

    group.bench_function("get_caseless_short_10b", |b| {
        b.iter(|| cache.get_caseless(black_box(short), false))
    });

    group.bench_function("get_caseless_long_200b", |b| {
        b.iter(|| cache.get_caseless(black_box(&long), false))
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_get_caseless_hit,
    bench_get_caseless_miss,
    bench_insert,
    bench_invalidate,
    bench_get_caseless_short_vs_long,
);
criterion_main!(benches);
