/// Minimal repro for os error 4395 (STATUS_REPARSE_POINT_ENCOUNTERED)
/// during removal of pywin32-311.data directory inside winrsbox sandbox.
///
/// This Rust repro is more faithful to uv's behavior than the Python one:
/// Rust std::fs::remove_dir_all on Windows uses NtCreateFile with
/// FILE_OPEN_REPARSE_POINT | FILE_DELETE_ON_CLOSE and
/// NtSetInformationFile(FileDispositionInformationEx, flags=DELETE|POSIX),
/// whereas Python's shutil.rmtree uses RemoveDirectoryW which follows a
/// different code path.
///
/// To compile and run inside the sandbox:
///   rustc --edition 2021 repro_rust_rmdir.rs -o repro_rust_rmdir.exe
///   winrsbox.exe --cwd D:\ai_dev\hermes -- repro_rust_rmdir.exe
///
/// Expected (bug present):  exit code 1, "The object manager encountered
///                          a reparse point while retrieving an object. (os error 4395)"
/// Expected (bug fixed):    exit code 0, "SUCCESS"

use std::fs;
use std::path::Path;

const DATA_DIR: &str =
    r"C:\users\computer\appdata\local\hermes\hermes-agent\venv\Lib\site-packages\pywin32-311.data";

fn main() {
    println!("[repro] Target: {DATA_DIR}");

    let path = Path::new(DATA_DIR);
    if !path.exists() {
        println!("[repro] SKIP: directory does not exist (sandbox not pre-seeded)");
        println!("[repro] Re-seed: run PowerShell to create the overlay directory:");
        println!("[repro]   $base = 'C:\\Users\\Computer\\AppData\\Local\\.winrsbox\\hermes\\workdir\\users\\computer\\appdata\\local\\hermes\\hermes-agent\\venv'");
        println!("[repro]   New-Item -ItemType Directory -Path \"$base\\lib\\site-packages\\pywin32-311.data\\scripts\" -Force");
        std::process::exit(0);
    }

    // Walk the tree first to report reparse point attributes
    fn walk_and_report(path: &Path) {
        match fs::symlink_metadata(path) {
            Ok(md) => {
                use std::os::windows::fs::MetadataExt;
                let attrs = md.file_attributes();
                let is_reparse = attrs & 0x400 != 0;
                println!("[repro]   {:?}  attrs=0x{:x}  reparse={}", path, attrs, is_reparse);
            }
            Err(e) => println!("[repro]   {:?}  ERROR: {}", path, e),
        }
        if path.is_dir() {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    walk_and_report(&entry.path());
                }
            }
        }
    }
    walk_and_report(path);

    println!("[repro] Attempting std::fs::remove_dir_all({DATA_DIR:?})");
    match fs::remove_dir_all(path) {
        Ok(()) => {
            println!("[repro] SUCCESS: remove_dir_all completed without error");
            std::process::exit(0);
        }
        Err(e) => {
            println!("[repro] FAIL: {e}");
            println!("[repro] kind={:?}  os_error={:?}", e.kind(), e.raw_os_error());
            std::process::exit(1);
        }
    }
}
