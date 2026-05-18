use criterion::{black_box, criterion_group, criterion_main, Criterion};
use policy::path;
use std::path::Path;

fn bench_nt_to_dos_with_prefix(c: &mut Criterion) {
    let mut group = c.benchmark_group("path");
    let raw: Vec<u16> = r"\??\C:\Users\alice\foo.txt".encode_utf16().collect();

    group.bench_function("nt_to_dos_with_prefix", |b| {
        b.iter(|| path::nt_to_dos(black_box(&raw)))
    });
    group.finish();
}

fn bench_nt_to_dos_no_prefix(c: &mut Criterion) {
    let mut group = c.benchmark_group("path");
    let raw: Vec<u16> = r"C:\Users\alice\foo.txt".encode_utf16().collect();

    group.bench_function("nt_to_dos_no_prefix", |b| {
        b.iter(|| path::nt_to_dos(black_box(&raw)))
    });
    group.finish();
}

fn bench_dos_to_nt(c: &mut Criterion) {
    let mut group = c.benchmark_group("path");

    group.bench_function("dos_to_nt", |b| {
        b.iter(|| path::dos_to_nt(black_box(r"C:\Users\alice\foo.txt")))
    });
    group.finish();
}

fn bench_mirror_into_overlay(c: &mut Criterion) {
    let mut group = c.benchmark_group("path");
    let root = Path::new(r"\sb");

    group.bench_function("mirror_into_overlay", |b| {
        b.iter(|| path::mirror_into_overlay(black_box(r"c:\users\alice\foo.txt"), black_box(root)))
    });
    group.finish();
}

fn bench_pattern_matches_prefix_hit(c: &mut Criterion) {
    let mut group = c.benchmark_group("path");

    group.bench_function("pattern_matches_prefix_hit", |b| {
        b.iter(|| path::pattern_matches_prefix(
            black_box(r"c:\users\*"),
            black_box(r"c:\users\alice\.ssh\id_rsa"),
        ))
    });
    group.finish();
}

fn bench_pattern_matches_prefix_miss(c: &mut Criterion) {
    let mut group = c.benchmark_group("path");

    group.bench_function("pattern_matches_prefix_miss", |b| {
        b.iter(|| path::pattern_matches_prefix(
            black_box(r"c:\windows"),
            black_box(r"c:\users\alice"),
        ))
    });
    group.finish();
}

fn bench_pattern_specificity(c: &mut Criterion) {
    let mut group = c.benchmark_group("path");

    group.bench_function("pattern_specificity", |b| {
        b.iter(|| path::pattern_specificity(black_box(r"c:\users\*\.ssh\*.pub")))
    });
    group.finish();
}

fn bench_nt_to_dos_lower_with_prefix(c: &mut Criterion) {
    let mut group = c.benchmark_group("path");
    let raw: Vec<u16> = r"\??\C:\Users\alice\foo.txt".encode_utf16().collect();

    group.bench_function("nt_to_dos_lower_with_prefix", |b| {
        b.iter(|| path::nt_to_dos_lower(black_box(&raw)))
    });
    group.finish();
}

fn bench_nt_to_dos_lower_no_prefix(c: &mut Criterion) {
    let mut group = c.benchmark_group("path");
    let raw: Vec<u16> = r"C:\Users\alice\foo.txt".encode_utf16().collect();

    group.bench_function("nt_to_dos_lower_no_prefix", |b| {
        b.iter(|| path::nt_to_dos_lower(black_box(&raw)))
    });
    group.finish();
}

fn bench_nt_to_dos_plus_lowercase(c: &mut Criterion) {
    let mut group = c.benchmark_group("path");
    let raw: Vec<u16> = r"\??\C:\Users\alice\foo.txt".encode_utf16().collect();

    group.bench_function("nt_to_dos_plus_lowercase", |b| {
        b.iter(|| {
            let s = path::nt_to_dos(black_box(&raw));
            s.map(|s| s.to_ascii_lowercase())
        })
    });
    group.finish();
}

fn bench_pattern_double_star_short(c: &mut Criterion) {
    let mut group = c.benchmark_group("path");

    group.bench_function("pattern_double_star_short", |b| {
        b.iter(|| path::pattern_matches_prefix(
            black_box(r"c:\users\**\.ssh"),
            black_box(r"c:\users\alice\.ssh"),
        ))
    });
    group.finish();
}

fn bench_pattern_double_star_long(c: &mut Criterion) {
    let mut group = c.benchmark_group("path");

    group.bench_function("pattern_double_star_long", |b| {
        b.iter(|| path::pattern_matches_prefix(
            black_box(r"c:\**\foo\**\.bar"),
            black_box(r"c:\a\b\c\foo\d\e\f\.bar"),
        ))
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_nt_to_dos_with_prefix,
    bench_nt_to_dos_no_prefix,
    bench_nt_to_dos_lower_with_prefix,
    bench_nt_to_dos_lower_no_prefix,
    bench_nt_to_dos_plus_lowercase,
    bench_dos_to_nt,
    bench_mirror_into_overlay,
    bench_pattern_matches_prefix_hit,
    bench_pattern_matches_prefix_miss,
    bench_pattern_specificity,
    bench_pattern_double_star_short,
    bench_pattern_double_star_long,
);
criterion_main!(benches);
