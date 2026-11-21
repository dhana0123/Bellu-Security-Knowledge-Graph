// Fails when a production dependency of ui/ has a license outside the allow list.
// Reads the production set from ui/package-lock.json (entries not marked dev) and the
// license field of each installed package.json in ui/node_modules (run npm ci first).
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ui = join(dirname(fileURLToPath(import.meta.url)), '..', 'ui');
const ALLOWED = new Set(['MIT', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'Apache-2.0', 'MPL-2.0', '0BSD', 'CC0-1.0']);
const EXTRA = { argparse: new Set(['Python-2.0']) };

function name(path) {
  return path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
}

// SPDX expression: OR needs one allowed alternative, AND needs all of them.
function ok(expr, allowed) {
  const e = expr.replace(/[()]/g, ' ').trim();
  if (/\s+OR\s+/i.test(e)) return e.split(/\s+OR\s+/i).some((p) => ok(p, allowed));
  if (/\s+AND\s+/i.test(e)) return e.split(/\s+AND\s+/i).every((p) => ok(p, allowed));
  return allowed.has(e.trim());
}

function licenseOf(pkg) {
  if (typeof pkg.license === 'string') return pkg.license;
  if (pkg.license && typeof pkg.license.type === 'string') return pkg.license.type;
  if (Array.isArray(pkg.licenses)) return pkg.licenses.map((l) => l.type ?? l).join(' OR ');
  return '';
}

const lock = JSON.parse(readFileSync(join(ui, 'package-lock.json'), 'utf8'));
const bad = [];
let checked = 0;
for (const [path, meta] of Object.entries(lock.packages ?? {})) {
  if (path === '' || meta.dev || meta.devOptional) continue;
  const dir = join(ui, path);
  const file = join(dir, 'package.json');
  if (!existsSync(file)) {
    if (meta.optional) continue; // optional platform package not installed here
    bad.push(`${path}: not installed (run npm ci)`);
    continue;
  }
  const n = name(path);
  const lic = licenseOf(JSON.parse(readFileSync(file, 'utf8'))) || String(meta.license ?? '');
  const allowed = new Set([...ALLOWED, ...(EXTRA[n] ?? [])]);
  checked++;
  if (!lic || !ok(lic, allowed)) bad.push(`${n}: ${lic || 'no license field'}`);
}
console.log(`ui-license-check: ${checked} production packages checked`);
if (bad.length > 0) {
  console.error('ui-license-check: disallowed licenses:\n  ' + bad.join('\n  '));
  process.exit(1);
}
