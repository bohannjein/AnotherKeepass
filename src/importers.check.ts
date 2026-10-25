// node src/importers.check.ts
import { parseCsv, parseImport, toImportInput } from './importers.ts';

const fail = (m: string) => { throw new Error(m); };
const assert = {
  equal: (a: unknown, b: unknown) => { if (a !== b) fail(String(a) + ' !== ' + String(b)); },
  deepEqual: (a: unknown, b: unknown) => { if (JSON.stringify(a) !== JSON.stringify(b)) fail(JSON.stringify(a) + ' !== ' + JSON.stringify(b)); },
  ok: (a: unknown) => { if (!a) fail('not ok'); },
  rejects: async (p: Promise<unknown>, re: RegExp) => { try { await p; } catch (e) { if (re.test(String(e))) return; fail(String(e)); } fail('did not reject'); },
};
const enc = (s: string) => new TextEncoder().encode(s).buffer as ArrayBuffer;
const val = (e: { fields: { key?: string; label?: string; value: string }[] }, k: string) => e.fields.find(f => f.key === k || f.label === k)?.value;

assert.deepEqual(parseCsv('a,"b ""q"", c"\r\n1,"multi\nline"\n'), [['a', 'b "q", c'], ['1', 'multi\nline']]);
assert.deepEqual(parseCsv('a;b\n1;2'), [['a', 'b'], ['1', '2']]);

// KeePassXC CSV: root group dropped, path split
let r = await parseImport('x.csv', enc('"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"\n"Root/Work/Mail","Mail","alice","pw1","https://mail.example","n","","0","",""'));
assert.equal(r.source, 'KeePassXC (CSV)');
assert.deepEqual(r.entries[0].path, ['Work', 'Mail']);
assert.equal(val(r.entries[0], 'password'), 'pw1');
assert.equal(r.entries[0].type, 'login');

// Bitwarden CSV with fields column and note type
r = await parseImport('bw.csv', enc('folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nSocial,1,login,Site,,"pin: 1234",0,https://a.com,bob,pw,JBSWY3DPEHPK3PXP\n,,note,Memo,text,,0,,,,'));
assert.equal(r.source, 'Bitwarden (CSV)');
assert.equal(val(r.entries[0], 'pin'), '1234');
assert.equal(r.entries[0].pinned, true);
assert.equal(r.entries[1].type, 'note');
const input = toImportInput(r.entries[0]);
assert.ok(input.item.fields.find(f => f.name === 'otp')!.value!.startsWith('otpauth://'));
assert.ok(input.item.tags.includes('pinned'));

// Chrome CSV: title from name
r = await parseImport('Chrome Passwords.csv', enc('name,url,username,password,note\nexample.com,https://example.com/login,me,secret,'));
assert.equal(r.entries[0].title, 'example.com');

// Bitwarden JSON
r = await parseImport('bw.json', enc(JSON.stringify({ encrypted: false, folders: [{ id: 'f', name: 'Bank' }], items: [
  { type: 1, name: 'L', folderId: 'f', login: { username: 'u', password: 'p', uris: [{ uri: 'https://a' }, { uri: 'https://b' }] }, fields: [{ name: 'secret q', value: 'x', type: 1 }] },
  { type: 3, name: 'Card', card: { cardholderName: 'J', number: '4111', expMonth: '3', expYear: '2030', code: '123' } },
] })));
assert.deepEqual(r.entries[0].path, ['Bank']);
assert.equal(val(r.entries[0], 'KP2A_URL'), 'https://b');
assert.equal(r.entries[0].fields.find(f => f.label === 'secret q')?.kind, 'hidden');
assert.equal(val(r.entries[1], 'expires'), '03/2030');
await assert.rejects(parseImport('e.json', enc('{"encrypted":true,"items":[]}')), /encrypted/);

// Proton Pass JSON, trashed item skipped
r = await parseImport('data.json', enc(JSON.stringify({ encrypted: false, vaults: { s: { name: 'Personal', items: [
  { state: 1, pinned: true, data: { type: 'login', metadata: { name: 'Proton', note: '' }, content: { itemEmail: 'a@b.c', itemUsername: '', password: 'pw', urls: ['https://proton.me'], totpUri: '' }, extraFields: [] } },
  { state: 2, data: { type: 'note', metadata: { name: 'old' }, content: {} } },
] } } })));
assert.equal(r.source, 'Proton Pass');
assert.equal(r.entries.length, 1);
assert.equal(r.skipped, 1);
assert.equal(val(r.entries[0], 'username'), 'a@b.c');

await assert.rejects(parseImport('x.txt', enc('hello world')), /empty|unknown_format/);

// ---- fuzzing: broken, truncated, mistyped and oversized files must give a result or an Error,
// never hang and never hand broken entries to the vault. Seeded, so failures reproduce.
let seed = 0x5eed;
const rnd = () => { seed = (seed + 0x6d2b79f5) | 0; let x = Math.imul(seed ^ (seed >>> 15), 1 | seed); x ^= x + Math.imul(x ^ (x >>> 7), 61 | x); return ((x ^ (x >>> 14)) >>> 0) / 2 ** 32; };
const pick = <T,>(a: T[]) => a[Math.floor(rnd() * a.length)];
const junk = [null, 0, -1, 1e308, '', 'x', true, [], {}, [null], { a: null }];
// replace random values deep inside a JSON document with values of the wrong type
const mutate = (v: unknown, depth = 0): unknown => {
  if (rnd() < 0.15) return pick(junk);
  if (Array.isArray(v)) return v.map(x => mutate(x, depth + 1));
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, mutate(x, depth + 1)]));
  return v;
};
const samples: [string, string][] = [
  ['bw.csv', 'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nSocial,1,login,Site,,"pin: 1234",0,https://a.com,bob,pw,JBSWY3DPEHPK3PXP'],
  ['x.csv', '"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"\n"Root/Work","Mail","alice","pw1","https://m","n","","0","",""'],
  ['bw.json', JSON.stringify({ encrypted: false, folders: [{ id: 'f', name: 'Bank' }], items: [{ type: 1, name: 'L', folderId: 'f', login: { username: 'u', password: 'p', uris: [{ uri: 'https://a' }] }, fields: [{ name: 'q', value: 'x', type: 1 }] }, { type: 3, name: 'C', card: { number: '4111', expMonth: '3', expYear: '2030' } }] })],
  ['data.json', JSON.stringify({ encrypted: false, vaults: { s: { name: 'P', items: [{ state: 1, data: { type: 'login', metadata: { name: 'Proton', note: '' }, content: { itemEmail: 'a@b.c', password: 'pw', urls: ['https://p'] }, extraFields: [{ fieldName: 'f', type: 'hidden', data: { content: 'v' } }] } }] } } })],
  ['1p.json', JSON.stringify({ accounts: [{ vaults: [{ attrs: { name: 'V' }, items: [{ state: 'active', overview: { title: 'T', url: 'https://t' }, details: { loginFields: [{ designation: 'username', value: 'u' }, { designation: 'password', value: 'p' }], sections: [{ fields: [{ title: 'pin', value: { concealed: '1' } }] }] } }] }] }] })],
];
const settle = async (name: string, bytes: ArrayBuffer) => {
  const timeout = new Promise<'hang'>(res => setTimeout(() => res('hang'), 3000));
  const out = await Promise.race([parseImport(name, bytes).then(r => r, e => e as unknown), timeout]);
  if (out === 'hang') fail(`hang: ${name}`);
  if (out instanceof Error) return;
  if (!out || typeof out !== 'object' || !Array.isArray((out as { entries?: unknown }).entries)) fail(`no result: ${name}`);
  for (const e of (out as { entries: Parameters<typeof toImportInput>[0][] }).entries) {
    if (typeof e.title !== 'string' || !Array.isArray(e.fields) || e.fields.some(f => typeof f.value !== 'string')) fail(`broken entry from ${name}: ${JSON.stringify(e).slice(0, 200)}`);
    toImportInput(e);
  }
};
for (let round = 0; round < 300; round++) {
  const [name, text] = pick(samples);
  const kind = round % 4;
  let input = text;
  if (kind === 0) input = text.slice(0, Math.floor(rnd() * text.length)); // truncated
  if (kind === 1 && name.endsWith('.json')) input = JSON.stringify(mutate(JSON.parse(text))); // wrong types
  if (kind === 2) input = [...text].map(c => rnd() < 0.02 ? String.fromCharCode(Math.floor(rnd() * 128)) : c).join(''); // flipped chars
  if (kind === 3) { // random bytes, sometimes posing as a zip
    const b = new Uint8Array(Math.floor(rnd() * 400)).map(() => Math.floor(rnd() * 256));
    if (rnd() < 0.5 && b.length > 4) { b[0] = 0x50; b[1] = 0x4b; b[2] = 3; b[3] = 4; }
    await settle(name, b.buffer);
    continue;
  }
  await settle(name, enc(input));
}
// oversized: 20 000 CSV rows parse in reasonable time
const big = 'name,url,username,password,note\n' + Array.from({ length: 20000 }, (_, i) => `site${i},https://s${i}.example,user${i},pw${i},`).join('\n');
const t0 = Date.now();
assert.equal((await parseImport('Chrome Passwords.csv', enc(big))).entries.length, 20000);
assert.ok(Date.now() - t0 < 5000);
console.log('importers ok');
