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
console.log('importers ok');
