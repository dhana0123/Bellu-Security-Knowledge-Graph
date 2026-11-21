// Fails when the total gzipped size of the JavaScript in ui/dist/assets exceeds the limit.
// Usage: node scripts/ui-size-check.mjs [limitKB]   (default 300)
import { readdirSync, readFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const dir = join(root, 'ui', 'dist', 'assets');
const limitKB = Number(process.argv[2] ?? process.env.UI_JS_GZIP_LIMIT_KB ?? 300);

let files;
try {
  files = readdirSync(dir).filter((f) => f.endsWith('.js'));
} catch {
  console.error(`ui-size-check: ${dir} not found; build the UI first`);
  process.exit(1);
}
if (files.length === 0) {
  console.error('ui-size-check: no .js files in ui/dist/assets');
  process.exit(1);
}
let total = 0;
for (const f of files) {
  const n = gzipSync(readFileSync(join(dir, f)), { level: 9 }).length;
  total += n;
  console.log(`${f}: ${(n / 1024).toFixed(1)} KB gzipped`);
}
const kb = total / 1024;
console.log(`total: ${kb.toFixed(1)} KB gzipped (limit ${limitKB} KB)`);
if (kb > limitKB) {
  console.error('ui-size-check: limit exceeded');
  process.exit(1);
}
