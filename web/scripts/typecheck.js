const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const NEXT_TYPES = path.resolve(ROOT, '.next/types');
const NEXT_DEV_TYPES = path.resolve(ROOT, '.next/dev/types');

fs.rmSync(NEXT_TYPES, { recursive: true, force: true });
fs.rmSync(NEXT_DEV_TYPES, { recursive: true, force: true });

const executable = process.platform === 'win32' ? 'bun.exe' : 'bun';
const result = spawnSync(executable, ['x', 'tsc', '--noEmit'], {
  cwd: ROOT,
  env: process.env,
  shell: false,
  stdio: 'inherit',
});

if (result.error) {
  throw result.error;
}
if (result.status !== 0) {
  process.exit(result.status || 1);
}
