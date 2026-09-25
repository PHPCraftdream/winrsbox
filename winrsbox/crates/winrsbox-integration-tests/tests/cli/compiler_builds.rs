use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

#[path = "../common/mod.rs"]
mod common;
use common::{find_hook_dll, find_launcher};

struct SandboxProject {
    _root: TempDir,
    project: PathBuf,
    temp: PathBuf,
    launcher: PathBuf,
    hook: PathBuf,
}

impl SandboxProject {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("create isolated compiler test root");
        let project = root.path().join("project");
        let state = root.path().join(".winrsbox").join("project");
        let temp = project.join(".tmp");
        fs::create_dir_all(&state.join("workdir")).expect("create sandbox state");
        fs::create_dir_all(&temp).expect("create project-local temp directory");
        fs::write(
            state.join("sandbox.ktav"),
            "defaults: {\n    read: passthrough\n    write: cow\n}\nrules: []\n",
        )
        .expect("write CoW sandbox policy");

        Self {
            _root: root,
            project,
            temp,
            launcher: find_launcher(),
            hook: find_hook_dll(),
        }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.project.join(relative)
    }

    fn environment(&self, extra: &[(&str, OsString)]) -> Vec<(String, OsString)> {
        let mut env = vec![
            (
                "FS_SANDBOX_DLL".to_owned(),
                self.hook.as_os_str().to_os_string(),
            ),
            ("TEMP".to_owned(), self.temp.as_os_str().to_os_string()),
            ("TMP".to_owned(), self.temp.as_os_str().to_os_string()),
            ("TMPDIR".to_owned(), self.temp.as_os_str().to_os_string()),
        ];
        env.extend(
            extra
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone())),
        );
        env
    }

    fn run(&self, program: &OsStr, args: &[OsString], env: &[(String, OsString)]) -> Output {
        let mut command = Command::new(&self.launcher);
        command
            .arg("-d")
            .arg("--")
            .arg(program)
            .args(args)
            .current_dir(&self.project);
        // Test Cargo/rustc themselves, not a host-wide cache wrapper.
        command.env_remove("RUSTC_WRAPPER");
        for (key, value) in env {
            command.env(key, value);
        }
        command.output().expect("launch compiler through winrsbox")
    }

    fn assert_host_output_present(&self, relative: &str) {
        let output = self.path(relative);
        let metadata = fs::metadata(&output)
            .unwrap_or_else(|e| panic!("compiler output missing at {}: {e}", output.display()));
        assert!(
            metadata.is_file() && metadata.len() > 0,
            "empty compiler output: {}",
            output.display()
        );
    }

    fn diagnostics(&self) -> String {
        let state = self._root.path().join(".winrsbox").join("project");
        let mut out = String::new();
        for name in ["sandbox.log.jsonl", "violations.log"] {
            if let Ok(text) = fs::read_to_string(state.join(name)) {
                let tail = text.lines().rev().take(40).collect::<Vec<_>>();
                if !tail.is_empty() {
                    out.push_str(&format!("\n{name}:\n"));
                    for line in tail.into_iter().rev() {
                        out.push_str(line);
                        out.push('\n');
                    }
                }
            }
        }
        out
    }
}

fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(|value| OsString::from(*value)).collect()
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

fn find_framework_csc() -> Option<PathBuf> {
    let root = std::env::var_os("WINDIR").or_else(|| std::env::var_os("SystemRoot"))?;
    [
        Path::new("Microsoft.NET/Framework64/v4.0.30319/csc.exe"),
        Path::new("Microsoft.NET/Framework/v4.0.30319/csc.exe"),
    ]
    .iter()
    .map(|relative| PathBuf::from(&root).join(relative))
    .find(|candidate| candidate.is_file())
}

fn skip_if_missing(missing: &[&str]) -> bool {
    if missing.is_empty() {
        return false;
    }
    let message = format!(
        "required compiler executable(s) not found: {}",
        missing.join(", ")
    );
    if std::env::var("WINRSBOX_REQUIRE_TOOLCHAINS").is_ok_and(|value| value == "1") {
        panic!("{message}");
    }
    eprintln!("SKIP: {message}");
    true
}

fn assert_success(project: &SandboxProject, label: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{label} failed ({}):\nstdout:\n{}\nstderr:\n{}{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        project.diagnostics()
    );
}

fn assert_stdout_contains(project: &SandboxProject, label: &str, output: &Output, marker: &str) {
    assert_success(project, label, output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(marker),
        "{label} did not print {marker:?}:\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn node_runtime_in_full_box() {
    let Some(node) = find_on_path("node.exe") else {
        skip_if_missing(&["node.exe"]);
        return;
    };
    let project = SandboxProject::new();
    let env = project.environment(&[]);
    let output = project.run(
        node.as_os_str(),
        &args(&["-e", "console.log('sandbox-node-ok')"]),
        &env,
    );
    assert_stdout_contains(&project, "Node.js runtime", &output, "sandbox-node-ok");
}

#[test]
fn python_runtime_in_full_box() {
    let Some(python) = find_on_path("python.exe") else {
        skip_if_missing(&["python.exe"]);
        return;
    };
    let project = SandboxProject::new();
    let env = project.environment(&[]);
    let output = project.run(
        python.as_os_str(),
        &args(&["-c", "print('sandbox-python-ok')"]),
        &env,
    );
    assert_stdout_contains(&project, "Python runtime", &output, "sandbox-python-ok");
}

#[test]
fn php_runtime_in_full_box() {
    let Some(php) = find_on_path("php.exe") else {
        skip_if_missing(&["php.exe"]);
        return;
    };
    let project = SandboxProject::new();
    let env = project.environment(&[]);
    let output = project.run(
        php.as_os_str(),
        &args(&["-n", "-r", "echo 'sandbox-php-ok';"]),
        &env,
    );
    assert_stdout_contains(&project, "PHP runtime", &output, "sandbox-php-ok");
}

#[test]
fn go_build_in_full_box() {
    let Some(go) = find_on_path("go.exe") else {
        skip_if_missing(&["go.exe"]);
        return;
    };
    let project = SandboxProject::new();
    fs::write(
        project.path("go.mod"),
        "module sandbox.local/compiletest\ngo 1.16\n",
    )
    .expect("write Go module");
    fs::write(
        project.path("main.go"),
        "package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"sandbox-go-ok\") }\n",
    )
    .expect("write Go source");
    let env = project.environment(&[
        ("GO111MODULE", "on".into()),
        ("GOTOOLCHAIN", "local".into()),
        ("GOWORK", "off".into()),
        ("GOENV", "off".into()),
        ("GOPROXY", "off".into()),
        ("GOSUMDB", "off".into()),
        ("GOCACHE", project.path(".cache/go-build").into_os_string()),
        ("GOMODCACHE", project.path(".cache/go-mod").into_os_string()),
        ("GOTMPDIR", project.temp.as_os_str().to_os_string()),
    ]);

    let built = project.run(
        go.as_os_str(),
        &args(&["build", "-o", "hello.exe", "."]),
        &env,
    );
    assert_success(&project, "go build", &built);
    project.assert_host_output_present("hello.exe");
}

#[test]
fn rust_cargo_build_in_full_box() {
    let Some(cargo) = find_on_path("cargo.exe") else {
        skip_if_missing(&["cargo.exe"]);
        return;
    };
    let project = SandboxProject::new();
    fs::create_dir_all(project.path("src")).expect("create Rust source directory");
    fs::write(
        project.path("Cargo.toml"),
        "[package]\nname = \"sandbox_compile_rust\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("write Rust manifest");
    fs::write(
        project.path("src/main.rs"),
        "fn main() { println!(\"sandbox-rust-ok\"); }\n",
    )
    .expect("write Rust source");
    let env = project.environment(&[
        ("CARGO_HOME", project.path(".cargo-home").into_os_string()),
        ("CARGO_TARGET_DIR", project.path("target").into_os_string()),
        ("CARGO_NET_OFFLINE", "true".into()),
        ("CARGO_INCREMENTAL", "0".into()),
    ]);

    let built = project.run(cargo.as_os_str(), &args(&["build", "--offline"]), &env);
    assert_success(&project, "cargo build --offline", &built);
    project.assert_host_output_present("target/debug/sandbox_compile_rust.exe");
}

#[test]
fn java_compile_in_full_box() {
    let javac = find_on_path("javac.exe");
    let mut missing = Vec::new();
    if javac.is_none() {
        missing.push("javac.exe");
    }
    if skip_if_missing(&missing) {
        return;
    }
    let javac = javac.expect("javac checked above");
    let project = SandboxProject::new();
    fs::create_dir_all(project.path(".classes")).expect("create Java output directory");
    fs::write(
        project.path("Main.java"),
        "public class Main { public static void main(String[] args) { System.out.println(\"sandbox-java-ok\"); } }\n",
    )
    .expect("write Java source");
    let env = project.environment(&[]);

    let compiled = project.run(
        javac.as_os_str(),
        &args(&["-J-Djava.io.tmpdir=.tmp", "-d", ".classes", "Main.java"]),
        &env,
    );
    assert_success(&project, "javac", &compiled);
    project.assert_host_output_present(".classes/Main.class");
}

#[test]
fn csharp_framework_compile_in_full_box() {
    let Some(csc) = find_framework_csc() else {
        skip_if_missing(&[".NET Framework csc.exe"]);
        return;
    };
    let project = SandboxProject::new();
    fs::write(
        project.path("main.cs"),
        "using System;\ninternal static class Program { private static void Main() { Console.WriteLine(\"sandbox-csharp-ok\"); } }\n",
    )
    .expect("write C# source");
    let env = project.environment(&[]);

    let compiled = project.run(
        csc.as_os_str(),
        &args(&["/nologo", "/out:hello.exe", "main.cs"]),
        &env,
    );
    assert_success(&project, ".NET Framework csc.exe", &compiled);
    project.assert_host_output_present("hello.exe");
}

#[test]
fn cpp_compile_in_full_box() {
    let compiler = ["cl.exe", "clang++.exe", "g++.exe"]
        .iter()
        .find_map(|name| find_on_path(name).map(|path| (*name, path)));
    if compiler.is_none() {
        skip_if_missing(&["cl.exe, clang++.exe, or g++.exe"]);
        return;
    }
    let (name, compiler) = compiler.expect("C++ compiler checked above");
    let project = SandboxProject::new();
    fs::write(
        project.path("main.cpp"),
        "#include <iostream>\nint main() { std::cout << \"sandbox-cpp-ok\\n\"; }\n",
    )
    .expect("write C++ source");
    let env = project.environment(&[]);

    let compile_args = if name == "cl.exe" {
        args(&[
            "/nologo",
            "/EHsc",
            "/Fe:hello.exe",
            "/Fo:hello.obj",
            "main.cpp",
        ])
    } else {
        args(&["-std=c++17", "-O0", "-o", "hello.exe", "main.cpp"])
    };
    let compiled = project.run(compiler.as_os_str(), &compile_args, &env);
    assert_success(&project, "C++ compile", &compiled);
    project.assert_host_output_present("hello.exe");
}
