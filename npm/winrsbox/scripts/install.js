#!/usr/bin/env node
// postinstall: build winrsbox.exe + hook.dll from source and stage them in
// native/ next to this script. hook.dll is a separate cdylib (crate `hook`)
// that `cargo install` never copies — both artifacts must be built and
// staged together for the sandbox to work (see repo history: a launcher
// with a missing hook.dll fails fast on find_hook_dll(), which is correct;
// the point here is to never let that missing-file case happen at all).
//
// Source pinning: the build source is pinned to the exact commit recorded in
// package.json `winrsboxSource.commit` for this package version — never the
// mutable HEAD of the upstream default branch. The checkout is verified
// against that commit (rev-parse HEAD) before any build is attempted and the
// build is refused otherwise.
//
// Binary integrity: after staging, an `integrity.json` SHA-256 manifest is
// written next to the staged binaries; the launcher verifies the manifest
// against them at every launch and fails closed on mismatch.

'use strict';

const { spawnSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PACKAGE_ROOT = path.join(__dirname, '..');
const NATIVE_DIR = path.join(PACKAGE_ROOT, 'native');
const pkg = JSON.parse(fs.readFileSync(path.join(PACKAGE_ROOT, 'package.json'), 'utf8'));
const REPO_URL = process.env.WINRSBOX_REPO_URL || 'https://github.com/PHPCraftdream/winrsbox.git';

// Exact upstream source commit this package version is built from. A checkout
// whose HEAD does not match this commit is never built.
const PINNED_COMMIT_CANDIDATE = pkg.winrsboxSource && pkg.winrsboxSource.commit;
const PINNED_COMMIT =
  typeof PINNED_COMMIT_CANDIDATE === 'string' && /^[0-9a-f]{40}$/.test(PINNED_COMMIT_CANDIDATE)
    ? PINNED_COMMIT_CANDIDATE
    : null;

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

function runCapture(cmd, args) {
  const result = spawnSync(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  return { ok: !result.error && result.status === 0, stdout: (result.stdout || '').toString().trim(), stderr: (result.stderr || '').toString().trim() };
}

function main() {
  if (process.platform !== 'win32' || process.arch !== 'x64') {
    fail(
      `unsupported platform ${process.platform}/${process.arch} — winrsbox ` +
      'only runs on Windows x64 (it hooks ntdll and uses the Windows ' +
      'Filtering Platform).'
    );
  }

  if (!PINNED_COMMIT) {
    fail('package.json winrsboxSource.commit must pin the exact source commit for this version.');
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
    const pinFile = path.join(srcDir, '.pin');

    // A leftover checkout may only be reused when it is exactly the pinned
    // commit — never blindly (a stale default-branch clone would silently
    // build different source than this package version was released with).
    const checkoutUsable =
      fs.existsSync(path.join(srcDir, 'winrsbox', 'Cargo.toml')) &&
      fs.existsSync(pinFile) &&
      fs.readFileSync(pinFile, 'utf8').trim() === PINNED_COMMIT &&
      runCapture('git', ['-C', srcDir, 'rev-parse', 'HEAD']).stdout === PINNED_COMMIT;

    if (!checkoutUsable) {
      fs.rmSync(srcDir, { recursive: true, force: true });
      fs.mkdirSync(srcDir, { recursive: true });
      console.log(`[winrsbox postinstall] cloning ${REPO_URL} at pinned commit ${PINNED_COMMIT}`);
      if (!run('git', ['clone', '--depth', '1', REPO_URL, srcDir])) {
        fail('git clone failed.');
      }
    }

    // A shallow clone lands on the default branch HEAD; when that is not the
    // pin (usual case: the branch moved on after release), fetch the exact
    // commit by SHA (GitHub supports fetch-by-sha) and detach onto it.
    if (runCapture('git', ['-C', srcDir, 'rev-parse', 'HEAD']).stdout !== PINNED_COMMIT) {
      console.log(`[winrsbox postinstall] fetching pinned source commit ${PINNED_COMMIT}`);
      if (!run('git', ['-C', srcDir, 'fetch', '--depth', '1', 'origin', PINNED_COMMIT])) {
        fail(
          `git fetch failed — could not fetch pinned source commit ${PINNED_COMMIT} ` +
          `from ${REPO_URL}.`
        );
      }
      const detach = runCapture('git', ['-C', srcDir, 'checkout', '--quiet', '--detach', 'FETCH_HEAD']);
      if (!detach.ok) {
        fail(`git checkout of pinned commit ${PINNED_COMMIT} failed: ${detach.stderr}`);
      }
    }

    // Final verification, before any build: refuse to build from anything but
    // the exact pinned commit.
    const actualHead = runCapture('git', ['-C', srcDir, 'rev-parse', 'HEAD']).stdout;
    if (actualHead !== PINNED_COMMIT) {
      fail(
        `source checkout does not match the pinned commit — refusing to build ` +
        `(expected ${PINNED_COMMIT}, found ${actualHead || 'no commit'}).`
      );
    }
    fs.writeFileSync(pinFile, `${PINNED_COMMIT}\n`);

    workspaceManifest = path.join(srcDir, 'winrsbox', 'Cargo.toml');
  }

  console.log('[winrsbox postinstall] cargo build --release (winrsbox + hook) — this takes a minute');
  const built = run('cargo', [
    'build', '--release', '--locked',
    '--manifest-path', workspaceManifest,
    '-p', 'winrsbox', '-p', 'winrsbox-hook',
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

  // Integrity manifest next to the staged binaries — the launcher verifies it
  // at every launch and fails closed on mismatch.
  const integrityFiles = {};
  for (const file of ['winrsbox.exe', 'hook.dll']) {
    integrityFiles[file] = crypto
      .createHash('sha256')
      .update(fs.readFileSync(path.join(NATIVE_DIR, file)))
      .digest('hex');
  }
  fs.writeFileSync(
    path.join(NATIVE_DIR, 'integrity.json'),
    JSON.stringify({ version: pkg.version, algorithm: 'sha256', files: integrityFiles }, null, 2) + '\n'
  );

  console.log(`[winrsbox postinstall] installed native/winrsbox.exe + native/hook.dll`);
  console.log('[winrsbox postinstall] wrote native/integrity.json (sha256 manifest, verified by the launcher at every launch)');
}

main();
