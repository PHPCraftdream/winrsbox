use criterion::{black_box, criterion_group, criterion_main, Criterion};
use winrsbox::etw::{self, EtwEventKind, EtwScoreboard};

fn bench_score_for_event(c: &mut Criterion) {
    c.bench_function("etw/score_for_event", |b| {
        b.iter(|| etw::score_for_event(black_box(EtwEventKind::DirectSyscallDetected)))
    });
}

fn bench_scoreboard_record(c: &mut Criterion) {
    let mut sb = EtwScoreboard::new();
    c.bench_function("etw/scoreboard_record", |b| {
        b.iter(|| sb.record(black_box(42), black_box(EtwEventKind::Other)))
    });
}

fn bench_parse_ti_event(c: &mut Criterion) {
    c.bench_function("etw/parse_ti_event_kind", |b| {
        b.iter(|| etw::parse_ti_event_kind(black_box(11)))
    });
}

fn bench_should_terminate(c: &mut Criterion) {
    c.bench_function("etw/should_terminate", |b| {
        b.iter(|| etw::should_terminate(black_box(24)))
    });
}

criterion_group!(benches, bench_score_for_event, bench_scoreboard_record, bench_parse_ti_event, bench_should_terminate);
criterion_main!(benches);
