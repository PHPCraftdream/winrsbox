// Clean payload: waits 30 seconds. Used as injection target by escape payloads.
fn main() {
    std::thread::sleep(std::time::Duration::from_secs(30));
}
