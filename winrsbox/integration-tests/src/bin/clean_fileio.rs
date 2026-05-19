// Clean payload: file I/O (read). Tests regression with FS hooks.
// Expected: runs to completion, not terminated by memory guard.

fn main() {
    match std::fs::read_to_string(r"C:\Windows\System32\drivers\etc\hosts") {
        Ok(content) => println!("hosts: {} bytes", content.len()),
        Err(e) => println!("read hosts: {e}"),
    }
    println!("clean_fileio ok");
}
