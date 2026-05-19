use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ipc::{write_msg, read_msg, Req, LogLevel};
use std::io::Cursor;

fn bench_encode_decide(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_msg");
    let msg = Req::Decide {
        dos_path: r"C:\Users\alice\foo.txt".to_owned(),
        write: false,
    };
    let mut buf = Cursor::new(Vec::new());

    group.bench_function("encode_decide", |b| {
        b.iter(|| {
            buf.set_position(0);
            buf.get_mut().clear();
            write_msg(&mut buf, black_box(&msg)).unwrap();
        })
    });
    group.finish();
}

fn bench_decode_decide(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_msg");
    let msg = Req::Decide {
        dos_path: r"C:\Users\alice\foo.txt".to_owned(),
        write: false,
    };
    let mut enc = Cursor::new(Vec::new());
    write_msg(&mut enc, &msg).unwrap();
    let encoded = enc.into_inner();

    group.bench_function("decode_decide", |b| {
        b.iter(|| {
            let mut cur = Cursor::new(black_box(&encoded[..]));
            let _: Req = read_msg(&mut cur).unwrap();
        })
    });
    group.finish();
}

fn bench_roundtrip_decide(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_msg");
    let msg = Req::Decide {
        dos_path: r"C:\Users\alice\foo.txt".to_owned(),
        write: false,
    };

    group.bench_function("roundtrip_decide", |b| {
        b.iter(|| {
            let mut buf = Cursor::new(Vec::new());
            write_msg(&mut buf, black_box(&msg)).unwrap();
            buf.set_position(0);
            let _: Req = read_msg(&mut buf).unwrap();
        })
    });
    group.finish();
}

fn bench_encode_log_short(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_msg");
    let msg = Req::Log {
        pid: 42,
        level: LogLevel::Info,
        msg: "hi".to_owned(),
    };
    let mut buf = Cursor::new(Vec::new());

    group.bench_function("encode_log_short", |b| {
        b.iter(|| {
            buf.set_position(0);
            buf.get_mut().clear();
            write_msg(&mut buf, black_box(&msg)).unwrap();
        })
    });
    group.finish();
}

fn bench_encode_log_long(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_msg");
    let msg = Req::Log {
        pid: 42,
        level: LogLevel::Info,
        msg: "x".repeat(4096),
    };
    let mut buf = Cursor::new(Vec::new());

    group.bench_function("encode_log_long", |b| {
        b.iter(|| {
            buf.set_position(0);
            buf.get_mut().clear();
            write_msg(&mut buf, black_box(&msg)).unwrap();
        })
    });
    group.finish();
}

fn bench_roundtrip_hello(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_msg");
    let msg = Req::Hello { pid: 42, exe_path: r"c:\program files\myapp\app.exe".into() };
    group.bench_function("roundtrip_hello", |b| {
        b.iter(|| {
            let mut buf = Cursor::new(Vec::new());
            write_msg(&mut buf, black_box(&msg)).unwrap();
            buf.set_position(0);
            let _: Req = read_msg(&mut buf).unwrap();
        })
    });
    group.finish();
}

fn bench_roundtrip_spawned_child(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_msg");
    let msg = Req::SpawnedChild {
        parent_pid: 1234, child_pid: 5678,
        child_exe: r"c:\windows\system32\cmd.exe".into(),
    };
    group.bench_function("roundtrip_spawned_child", |b| {
        b.iter(|| {
            let mut buf = Cursor::new(Vec::new());
            write_msg(&mut buf, black_box(&msg)).unwrap();
            buf.set_position(0);
            let _: Req = read_msg(&mut buf).unwrap();
        })
    });
    group.finish();
}

fn bench_roundtrip_record_overlay(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_msg");
    let msg = Req::RecordOverlay {
        orig: r"c:\users\alice\doc.txt".into(),
        overlay: r"c:\sb\c\users\alice\doc.txt".into(),
    };
    group.bench_function("roundtrip_record_overlay", |b| {
        b.iter(|| {
            let mut buf = Cursor::new(Vec::new());
            write_msg(&mut buf, black_box(&msg)).unwrap();
            buf.set_position(0);
            let _: Req = read_msg(&mut buf).unwrap();
        })
    });
    group.finish();
}

fn bench_roundtrip_memory_violation(c: &mut Criterion) {
    let mut group = c.benchmark_group("ipc_msg");
    let msg = Req::MemoryViolation {
        pid: 1234,
        exe: r"c:\app\target.exe".into(),
        kind: ipc::AllocKind::Allocate,
        requested_protect: 0x40,
        region_size: 4096,
        target_address: 0x7ff800000000,
        caller_pc: 0x7ff8a1234567,
        caller_module: Some(r"c:\users\x\evil.dll".into()),
        stack_top: vec![0x7ff8a1234567, 0x7ff8a1234568, 0x7ff8a1234569, 0x7ff8a123456a],
    };
    group.bench_function("roundtrip_memory_violation", |b| {
        b.iter(|| {
            let mut buf = Cursor::new(Vec::new());
            write_msg(&mut buf, black_box(&msg)).unwrap();
            buf.set_position(0);
            let _: Req = read_msg(&mut buf).unwrap();
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_encode_decide,
    bench_decode_decide,
    bench_roundtrip_decide,
    bench_encode_log_short,
    bench_encode_log_long,
    bench_roundtrip_hello,
    bench_roundtrip_spawned_child,
    bench_roundtrip_record_overlay,
    bench_roundtrip_memory_violation,
);
criterion_main!(benches);
