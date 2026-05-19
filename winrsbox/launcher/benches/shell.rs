use criterion::{black_box, criterion_group, criterion_main, Criterion};
use winrsbox::cli::shell;

fn bench_compose_command(c: &mut Criterion) {
    let mut g = c.benchmark_group("shell");
    g.bench_function("compose_command_wezterm", |b| {
        b.iter(|| {
            shell::compose_command(
                black_box(r"C:\bin\winrsbox.exe"),
                black_box(r"C:\Program Files\WezTerm\wezterm-gui.exe"),
                black_box(&["start"]),
                false,
            )
        })
    });
    g.bench_function("compose_command_pwsh", |b| {
        b.iter(|| {
            shell::compose_command(
                black_box(r"C:\bin\winrsbox.exe"),
                black_box(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
                black_box(&["-NoLogo"]),
                false,
            )
        })
    });
    g.finish();
}

fn bench_extract_target(c: &mut Criterion) {
    let mut g = c.benchmark_group("shell");
    let cmd = r#""C:\bin\winrsbox.exe" --cwd "%V" -- "C:\wezterm\wezterm-gui.exe" start"#;
    g.bench_function("extract_target_from_command", |b| {
        b.iter(|| shell::extract_target_from_command(black_box(cmd)))
    });
    g.finish();
}

fn bench_extract_extra_args(c: &mut Criterion) {
    let mut g = c.benchmark_group("shell");
    let cmd = r#""C:\bin\winrsbox.exe" --cwd "%V" -- "C:\pwsh\pwsh.exe" -NoLogo -NoProfile"#;
    g.bench_function("extract_extra_args_from_command", |b| {
        b.iter(|| shell::extract_extra_args_from_command(black_box(cmd)))
    });
    g.finish();
}

fn bench_find_in_path(c: &mut Criterion) {
    let mut g = c.benchmark_group("shell");
    g.bench_function("find_in_path_hit_cmd", |b| {
        b.iter(|| shell::find_in_path(black_box("cmd.exe")))
    });
    g.bench_function("find_in_path_miss", |b| {
        b.iter(|| shell::find_in_path(black_box("this-binary-definitely-does-not-exist.exe")))
    });
    g.finish();
}

fn bench_extract_flag(c: &mut Criterion) {
    let mut g = c.benchmark_group("shell");
    let args: Vec<String> = vec![
        "install".into(),
        "--wezterm".into(),
        r"C:\Program Files\WezTerm\wezterm-gui.exe".into(),
        "--pwsh".into(),
        r"C:\Program Files\PowerShell\7\pwsh.exe".into(),
    ];
    g.bench_function("extract_flag_hit_separated", |b| {
        b.iter(|| shell::extract_flag(black_box(&args), "--wezterm"))
    });

    let args_eq: Vec<String> = vec![
        "install".into(),
        r"--wezterm=C:\wez.exe".into(),
    ];
    g.bench_function("extract_flag_hit_equals", |b| {
        b.iter(|| shell::extract_flag(black_box(&args_eq), "--wezterm"))
    });
    g.bench_function("extract_flag_miss", |b| {
        b.iter(|| shell::extract_flag(black_box(&args), "--missing"))
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_compose_command,
    bench_extract_target,
    bench_extract_extra_args,
    bench_find_in_path,
    bench_extract_flag,
);
criterion_main!(benches);
