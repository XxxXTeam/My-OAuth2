/**
 * 跨平台构建脚本
 * 功能：清理 dist 目录 → 执行 next build → 复制 out 到 dist
 */
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const DIST = path.resolve(ROOT, '../server/web/dist');
const OUT = path.resolve(ROOT, 'out');

/* 递归复制目录 */
function copyDir(src, dest) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDir(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

/* 1. 清理 dist */
console.log('[build] 清理 dist 目录...');
fs.rmSync(DIST, { recursive: true, force: true });
fs.mkdirSync(DIST, { recursive: true });

/* 2. 执行 next build */
console.log('[build] 执行 next build...');
execSync('bunx next build', { cwd: ROOT, stdio: 'inherit' });

/* 3. 复制 out → dist */
console.log('[build] 复制构建产物到 dist...');
if (fs.existsSync(OUT)) {
  copyDir(OUT, DIST);
  console.log('[build] 完成!');
} else {
  console.error('[build] 错误: out 目录不存在，请确认 next.config 已配置 output: "export"');
  process.exit(1);
}
