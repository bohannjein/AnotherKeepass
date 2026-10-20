// Shrinks the Material Symbols font (5.4 MB) to the icons the app uses.
// Icons are ligatures ("content_copy" → glyph), so we keep every name that appears as a
// string literal in src/ plus all characters they're made of, pin the axes we don't vary
// (wght 450, opsz 24, GRAD 0) and keep FILL (0..1) for filled icons.
// Run: node scripts/subset-icons.mjs   (also part of `npm run build`)
import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import subsetFont from 'subset-font';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const files = [];
(function walk(dir) {
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) walk(p);
    else if (/\.(tsx?|css)$/.test(f) && !f.endsWith('.check.ts')) files.push(p);
  }
})(join(root, 'src'));

const names = new Set();
for (const f of files) {
  const src = readFileSync(f, 'utf8');
  for (const m of src.matchAll(/['"`]([a-z][a-z0-9_]{1,40})['"`]/g)) names.add(m[1]);
}
// letters of every name must stay, or the ligature can't form
const text = [...names].join(' ') + ' abcdefghijklmnopqrstuvwxyz0123456789_';

const input = readFileSync(join(root, 'node_modules/material-symbols/material-symbols-rounded.woff2'));
const out = await subsetFont(input, text, {
  targetFormat: 'woff2',
  variationAxes: { wght: 450, opsz: 24, GRAD: 0 },
});
writeFileSync(join(root, 'src/assets/material-symbols-subset.woff2'), out);
console.log(`icons: ${names.size} candidate names, ${(input.length / 1024).toFixed(0)} KB → ${(out.length / 1024).toFixed(0)} KB`);
