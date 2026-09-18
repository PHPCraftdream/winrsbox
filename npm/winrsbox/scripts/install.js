#!/usr/bin/env node
// postinstall: build winrsbox.exe + hook.dll from source and stage them in
// native/ next to this script. hook.dll is a separate cdylib (crate `hook`)
// that `cargo install` never copies — both artifacts must be built and
// staged together for the sandbox to work (see repo history: a launcher
// with a missing hook.dll fails fast on find_hook_dll(), which is correct;
// the point here is to never let that missing-file case happen at all).

'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const PACKAGE_ROOT = path.join(__dirname, '..');
const NATIVE_DIR = path.join(PACKAGE_ROOT, 'native');
const REPO_URL = 'https://github.com/PHPCraftdream/winrsbox.git';

function fail(msg) {
  console.error(`[winrsbox postinstall] ${msg}`);
  process.exit(1);
}

function run(cmd, args, opts) {
  const result = spawnSync(cmd, args, { stdio: 'inherit', ...opts });
  if (result.error) {
    throw result.error;
  }
  return result.status === 0;
}

function haveCommand(cmd) {
  const result = spawnSync(cmd, ['--version'], { stdio: 'ignore' });
  return !result.error && result.status === 0;
}

function main() {
  if (process.platform !== 'win32' || process.arch !== 'x64') {
    fail(
      `unsupported platform ${process.platform}/${process.arch} — winrsbox ` +
      'only runs on Windows x64 (it hooks ntdll and uses the Windows ' +
      'Filtering Platform).'
    );
  }

  if (!haveCommand('cargo')) {
    fail(
      'cargo (Rust toolchain) not found on PATH. winrsbox is installed by ' +
      'building it from source — install Rust first: https://rustup.rs'
    );
  }

  // Dev-friendly fast path: if this package lives inside a checkout of the
  // winrsbox monorepo (npm/winrsbox/ sibling of winrsbox/), build straight
  // from there — no clone, no throwaway copy.
  const localWorkspace = path.join(PACKAGE_ROOT, '..', '..', 'winrsbox', 'Cargo.toml');
  let workspaceManifest;

  if (fs.existsSync(localWorkspace)) {
    console.log('[winrsbox postinstall] found local workspace, building in place');
    workspaceManifest = localWorkspace;
  } else {
    if (!haveCommand('git')) {
      fail('git not found on PATH — required to fetch winrsbox source for the build.');
    }
    const srcDir = path.join(NATIVE_DIR, '.src');
    if (!fs.existsSync(path.join(srcDir, 'winrsbox', 'Cargo.toml'))) {
      fs.rmSync(srcDir, { recursive: true, force: true });
      fs.mkdirSync(srcDir, { recursive: true });
      console.log(`[winrsbox postinstall] cloning ${REPO_URL}`);
      if (!run('git', ['clone', '--depth', '1', REPO_URL, srcDir])) {
        fail('git clone failed.');
      }
    }
    workspaceManifest = path.join(srcDir, 'winrsbox', 'Cargo.toml');
  }

  console.log('[winrsbox postinstall] cargo build --release (winrsbox + hook) — this takes a minute');
  const built = run('cargo', [
    'build', '--release', '--locked',
    '--manifest-path', workspaceManifest,
    '-p', 'winrsbox', '-p', 'hook',
  ]);
  if (!built) {
    fail('cargo build failed — see output above.');
  }

  const targetRelease = path.join(path.dirname(workspaceManifest), 'target', 'release');
  fs.mkdirSync(NATIVE_DIR, { recursive: true });
  for (const file of ['winrsbox.exe', 'hook.dll']) {
    const src = path.join(targetRelease, file);
    if (!fs.existsSync(src)) {
      fail(`build did not produce ${file} at ${src}`);
    }
    fs.copyFileSync(src, path.join(NATIVE_DIR, file));
  }

  console.log(`[winrsbox postinstall] installed native/winrsbox.exe + native/hook.dll`);
}

main();
