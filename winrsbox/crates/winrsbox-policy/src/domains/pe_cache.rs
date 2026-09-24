use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use xxhash_rust::xxh3::Xxh3;

const SEED_A: u64 = 0x23c8_6e0a_b71d_496f;
const SEED_B: u64 = 0xa781_30cf_5d29_e4b3;
const BUFFER_BYTES: usize = 1024 * 1024;

/// A fast content identity, not a cryptographic authenticity proof.
pub fn file_key(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    let modified = before
        .modified()?
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mtime predates epoch"))?
        .as_nanos();
    let mut a = Xxh3::with_seed(SEED_A);
    let mut b = Xxh3::with_seed(SEED_B);
    for hasher in [&mut a, &mut b] {
        hasher.update(&before.len().to_le_bytes());
        hasher.update(&modified.to_le_bytes());
    }
    let mut buffer = vec![0u8; BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        a.update(&buffer[..read]);
        b.update(&buffer[..read]);
    }
    let after = file.metadata()?;
    if before.len() != after.len() || before.modified()? != after.modified()? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file changed while hashing",
        ));
    }
    Ok(format!("{:032x}{:032x}", a.digest128(), b.digest128()))
}

pub fn cache_dir(binary_dir: &Path) -> PathBuf {
    binary_dir.join("pe-scan-cache-v1")
}

fn entry_path(dir: &Path, key: &str) -> io::Result<PathBuf> {
    if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid scan cache key",
        ));
    }
    Ok(dir.join(key))
}

pub fn contains_clean(dir: &Path, key: &str) -> bool {
    entry_path(dir, key)
        .ok()
        .and_then(|path| fs::read(path).ok())
        .is_some_and(|marker| marker == b"clean\n")
}

pub fn record_clean(dir: &Path, key: &str) -> io::Result<()> {
    let path = entry_path(dir, key)?;
    fs::create_dir_all(dir)?;
    fs::write(path, b"clean\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_content_invalidates_even_when_length_matches() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("tool.exe");
        fs::write(&file, b"abcd").unwrap();
        let original_mtime = file.metadata().unwrap().modified().unwrap();
        let first = file_key(&file).unwrap();
        record_clean(temp.path(), &first).unwrap();
        assert!(contains_clean(temp.path(), &first));
        fs::write(&file, b"abce").unwrap();
        File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(original_mtime))
            .unwrap();
        assert_ne!(first, file_key(&file).unwrap());
    }

    #[test]
    fn changed_mtime_invalidates_unchanged_content() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("tool.exe");
        fs::write(&file, b"abcd").unwrap();
        let first = file_key(&file).unwrap();
        File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_times(
                fs::FileTimes::new().set_modified(
                    std::time::SystemTime::now() + std::time::Duration::from_secs(60),
                ),
            )
            .unwrap();
        assert_ne!(first, file_key(&file).unwrap());
    }

    #[test]
    fn invalid_key_cannot_escape_cache_directory() {
        let temp = tempfile::tempdir().unwrap();
        assert!(record_clean(temp.path(), "../outside").is_err());
    }
}
