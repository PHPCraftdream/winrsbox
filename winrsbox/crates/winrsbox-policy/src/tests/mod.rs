use crate::*;
use std::path::PathBuf;

mod core_tests;
mod project_tests;
mod whiteout_tests;
mod overlay_case_tests;

fn make_policy_with_project(project_name: &str) -> (tempfile::TempDir, Policy, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("policy.redb");
    let sandbox = dir.path().join("sb");
    let mock_dirs = dir.path().join("md");
    let project = dir.path().join(project_name);
    std::fs::create_dir_all(&sandbox).unwrap();
    std::fs::create_dir_all(&mock_dirs).unwrap();
    std::fs::create_dir_all(&project).unwrap();
    let p = Policy::open_or_create(&db_path, sandbox, mock_dirs, project.clone()).unwrap();
    (dir, p, project)
}
