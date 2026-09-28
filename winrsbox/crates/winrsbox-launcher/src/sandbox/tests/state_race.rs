// MP-2: `ensure_state` is called by both the eventual broker and, in the
// same brand-new folder, a losing client — before either has decided a role
// (role selection happens after `ensure_state`). Both hit the same
// not-yet-existing `.winrsbox/<name>/{workdir,mock-dirs,sandbox.ktav}` tree
// concurrently. This pins the fix: no thread observes an error, and exactly
// one `sandbox.ktav` (a single complete write, never a torn/partial one)
// exists afterward.
use super::*;

#[test]
fn ensure_state_concurrent_first_run_has_no_errors_and_one_config_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // ensure_state keys off <project_root>/../.winrsbox/<project_root-name>;
    // project_root itself need not exist beforehand.
    let project_root = tmp.path().join("myproj");

    const THREADS: usize = 8;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(THREADS));
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let barrier = std::sync::Arc::clone(&barrier);
            let project_root = project_root.clone();
            std::thread::spawn(move || {
                barrier.wait();
                ensure_state(&project_root)
            })
        })
        .collect();

    let mut cfg_paths = std::collections::HashSet::new();
    for h in handles {
        let (cfg_path, workdir, mock_dirs) = h
            .join()
            .expect("ensure_state thread panicked")
            .expect("ensure_state must not error under a concurrent first-run race");
        cfg_paths.insert(cfg_path);
        assert!(workdir.is_dir());
        assert!(mock_dirs.is_dir());
    }
    assert_eq!(
        cfg_paths.len(),
        1,
        "every thread must agree on the same cfg_path"
    );

    let cfg_path = cfg_paths.into_iter().next().unwrap();
    assert!(cfg_path.is_file(), "sandbox.ktav must exist exactly once");
    let contents = std::fs::read_to_string(&cfg_path).expect("read sandbox.ktav");
    assert_eq!(
        contents, DEFAULT_CONFIG_KTAV,
        "config file must be exactly one complete write, never a torn/partial one"
    );
}
