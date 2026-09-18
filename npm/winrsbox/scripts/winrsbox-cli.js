#!/usr/bin/env node
// Thin shim: `winrsbox` on PATH forwards straight to the native binary
// staged by scripts/install.js. No arg parsing here — winrsbox.exe owns
// its own CLI surface.

'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const exe = path.join(__dirname, '..', 'native', 'winrsbox.exe');

if (!fs.existsSync(exe)) {
  console.error(
    '[winrsbox] native/winrsbox.exe missing — the postinstall build did not ' +
    'complete. Reinstall the package (npm install) or run its postinstall ' +
    'script manually: node scripts/install.js'
  );
  process.exit(1);
}

const result = spawnSync(exe, process.argv.slice(2), { stdio: 'inherit' });
if (result.error) {
  console.error(`[winrsbox] failed to launch native binary: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status === null ? 1 : result.status);
