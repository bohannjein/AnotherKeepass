// Packs the built app into an MSIX for the Microsoft Store (unsigned: the Store signs it).
//   npx tauri build --no-bundle      (builds src-tauri/target/release/anotherkeepass.exe)
//   node scripts/build-msix.mjs
// Values from Partner Center (Product management > Product identity), as environment variables:
//   MSIX_IDENTITY_NAME   e.g. 12345JohannBeinsen.AnotherKeepass
//   MSIX_PUBLISHER       e.g. CN=12345678-ABCD-...
//   MSIX_PUBLISHER_NAME  e.g. Johann Beinsen
// Without them, placeholder values are used (fine for a local test pack, not for upload).
import { execFileSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version.split('-')[0] + '.0';
const exe = join(root, 'src-tauri/target/release/anotherkeepass.exe');
if (!existsSync(exe)) throw new Error('build first: npx tauri build --no-bundle');

const values = {
  IDENTITY_NAME: process.env.MSIX_IDENTITY_NAME || 'AnotherKeepass.Test',
  PUBLISHER: process.env.MSIX_PUBLISHER || 'CN=AnotherKeepass Test',
  PUBLISHER_NAME: process.env.MSIX_PUBLISHER_NAME || 'Johann Beinsen',
  VERSION: version,
};
const xmlEscape = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
const manifest = readFileSync(join(root, 'msix/AppxManifest.xml'), 'utf8')
  .replace(/\{\{(\w+)\}\}/g, (_, k) => xmlEscape(values[k] ?? ''));

const stage = join(root, 'src-tauri/target/msix');
rmSync(stage, { recursive: true, force: true });
mkdirSync(join(stage, 'Assets'), { recursive: true });
writeFileSync(join(stage, 'AppxManifest.xml'), manifest);
copyFileSync(exe, join(stage, 'anotherkeepass.exe'));
for (const f of ['Square150x150Logo.png', 'Square44x44Logo.png', 'StoreLogo.png']) {
  copyFileSync(join(root, 'src-tauri/icons', f), join(stage, 'Assets', f));
}

// makeappx from the newest installed Windows SDK
const kits = 'C:/Program Files (x86)/Windows Kits/10/bin';
const sdk = readdirSync(kits).filter(d => /^10\./.test(d) && existsSync(join(kits, d, 'x64/makeappx.exe'))).sort().pop();
if (!sdk) throw new Error('makeappx.exe not found (Windows SDK)');
const out = join(root, `src-tauri/target/AnotherKeepass_${version}_x64.msix`);
execFileSync(join(kits, sdk, 'x64/makeappx.exe'), ['pack', '/d', stage, '/p', out, '/o'], { stdio: 'inherit' });
console.log('msix:', out);
