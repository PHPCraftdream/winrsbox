// Clean payload: waits 30 seconds. Used as injection target by escape payloads.
//
// MP-10 integration test seam: when `WINRSBOX_SLEEP_WRITE_PATH` is set, this
// writes `WINRSBOX_SLEEP_WRITE_CONTENT` (default empty) to that path BEFORE
// sleeping — lets a test give a long-lived (broker) guest a one-shot CoW
// write of its own, same env-var-opt-in shape as `clean_fileio`'s MP-9 loop
// mode. A write failure exits loudly (3) instead of sleeping through it.
fn main() -> std::process::ExitCode {
    if let Ok(path) = std::env::var("WINRSBOX_SLEEP_WRITE_PATH") {
        let content = std::env::var("WINRSBOX_SLEEP_WRITE_CONTENT").unwrap_or_default();
        if let Err(e) = std::fs::write(&path, content.as_bytes()) {
            eprintln!("write {path} failed: {e}");
            return std::process::ExitCode::from(3);
        }
    }
    std::thread::sleep(std::time::Duration::from_secs(30));
    std::process::ExitCode::from(0)
}
