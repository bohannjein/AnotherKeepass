// Retakes the website screenshots (docs/img) from the browser demo. Needs `npm run dev` on :5173
// and Microsoft Edge. Run: node scripts/site-screenshots.mjs
import { spawn } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const OUT = 'docs/img';
const EDGE = process.env.EDGE ?? 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';
const port = 9333;
const edge = spawn(EDGE, ['--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${mkdtempSync(join(tmpdir(), 'akp-shot-'))}`, '--hide-scrollbars', 'about:blank']);
const sleep = ms => new Promise(r => setTimeout(r, ms));

let targets = [];
for (let i = 0; i < 50 && !targets.some(t => t.type === 'page'); i++) {
  try { targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); } catch { await sleep(200); }
}
const ws = new WebSocket(targets.find(t => t.type === 'page').webSocketDebuggerUrl);
await new Promise(r => ws.addEventListener('open', r));
let id = 0; const pending = new Map();
ws.addEventListener('message', e => { const m = JSON.parse(e.data); pending.get(m.id)?.(m); pending.delete(m.id); });
const cdp = (method, params = {}) => new Promise((res, rej) => { const i = ++id; pending.set(i, m => m.error ? rej(new Error(`${method}: ${m.error.message}`)) : res(m.result)); ws.send(JSON.stringify({ id: i, method, params })); });
const js = async expr => (await cdp('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true })).result.value;

// click the first button whose aria-label or text contains `label`
const click = async label => {
  const ok = await js(`(() => { const t = e => (e.getAttribute('aria-label') || e.textContent || '').trim();
    const els = [...document.querySelectorAll('button,[role=button],[role=option],li')];
    const el = els.find(e => t(e) === ${JSON.stringify(label)}) || els.find(e => t(e).includes(${JSON.stringify(label)}));
    el?.click(); return !!el; })()`);
  if (!ok) throw new Error('not found: ' + label);
  await sleep(500);
};
const unlock = async () => { await js(`document.querySelector('input[type=password]').focus()`); await cdp('Input.insertText', { text: 'demo' }); await click('Entsperren'); await sleep(1200); };
const start = async theme => {
  await cdp('Page.navigate', { url: 'http://localhost:5173/' }); await sleep(800);
  await js(`localStorage.clear(); localStorage.setItem('anotherkeepass.settings', JSON.stringify({ lang: 'de', theme: '${theme}' }))`);
  await cdp('Page.navigate', { url: 'http://localhost:5173/' }); await sleep(1500);
  await unlock();
  await click('Personal'); await unlock();
  await click('Work'); await unlock();
  await click('Alle Tresore');
};
// the largest dialog on screen, for cropped shots
const dialog = () => js(`(() => { const r = [...document.querySelectorAll('[role=dialog],dialog,[class*=dialog],[class*=palette],[class*=sheet]')]
  .map(e => e.getBoundingClientRect()).filter(r => r.width > 300 && r.width < 1100).sort((a, b) => b.width * b.height - a.width * a.height)[0];
  return { x: r.x, y: r.y, width: r.width, height: r.height, scale: 1 }; })()`);
const shot = async (name, clip) => {
  await sleep(700);
  const { data } = await cdp('Page.captureScreenshot', { format: 'webp', quality: 86, ...(clip && { clip }) });
  writeFileSync(join(OUT, name + '.webp'), Buffer.from(data, 'base64'));
  console.log('saved', name);
};

await cdp('Page.enable');
await cdp('Emulation.setDeviceMetricsOverride', { width: 1280, height: 800, deviceScaleFactor: 2, mobile: false });

await start('dark');
await click('Proton login'); await shot('app-dark');
await cdp('Input.dispatchKeyEvent', { type: 'keyDown', key: 'k', code: 'KeyK', modifiers: 2, windowsVirtualKeyCode: 75 });
await cdp('Input.dispatchKeyEvent', { type: 'keyUp', key: 'k', code: 'KeyK', modifiers: 2, windowsVirtualKeyCode: 75 });
await sleep(600); await shot('palette-crop', await dialog());
await click('Passwortgenerator'); await sleep(800); await shot('generator-crop', await dialog());

await start('light');
await click('GitHub'); await shot('app-light');

ws.close(); edge.kill();
