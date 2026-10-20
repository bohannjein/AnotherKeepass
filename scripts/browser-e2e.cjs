// End-to-end check of the KeePassXC-Browser protocol against our server, using tweetnacl
// exactly like the keepassxc-browser extension. Run by the ignored Rust test
// `browser_pipe_e2e` (it starts the server on AKP_PIPE_NAME with a test vault).
const net = require('net');
const nacl = require('tweetnacl');

const b64 = u8 => Buffer.from(u8).toString('base64');
const unb64 = s => new Uint8Array(Buffer.from(s, 'base64'));
const inc = n => { const r = new Uint8Array(n); for (let i = 0; i < r.length; i++) { r[i] = (r[i] + 1) & 255; if (r[i]) break; } return r; };

const pipe = process.env.AKP_PIPE_NAME;
const client = nacl.box.keyPair();
const idKey = nacl.box.keyPair();
let hostKey;
const sock = net.connect(pipe);
const fail = msg => { console.error('FAIL:', msg); process.exit(1); };
setTimeout(() => fail('timeout'), 15000);

let waiting;
sock.on('data', d => { const w = waiting; waiting = null; w && w(JSON.parse(d.toString())); });
const send = obj => new Promise(res => { waiting = res; sock.write(JSON.stringify(obj)); });
async function call(action, payload) {
  const nonce = nacl.randomBytes(24);
  const msg = nacl.box(Buffer.from(JSON.stringify({ action, ...payload })), nonce, hostKey, client.secretKey);
  const r = await send({ action, message: b64(msg), nonce: b64(nonce), clientID: 'e2e' });
  if (r.error) return r;
  if (b64(inc(nonce)) !== r.nonce) fail(`${action}: nonce not incremented`);
  const plain = nacl.box.open(unb64(r.message), unb64(r.nonce), hostKey, client.secretKey);
  if (!plain) fail(`${action}: cannot decrypt reply`);
  return JSON.parse(Buffer.from(plain).toString());
}

sock.on('connect', async () => {
  const n = nacl.randomBytes(24);
  const r = await send({ action: 'change-public-keys', publicKey: b64(client.publicKey), nonce: b64(n), clientID: 'e2e' });
  if (r.success !== 'true' || r.nonce !== b64(inc(n))) fail('change-public-keys ' + JSON.stringify(r));
  hostKey = unb64(r.publicKey);

  const hash = await call('get-databasehash', {});
  if (!/^[0-9a-f]{64}$/.test(hash.hash)) fail('hash ' + JSON.stringify(hash));

  const assoc = await call('associate', { key: b64(client.publicKey), idKey: b64(idKey.publicKey) });
  if (assoc.success !== 'true' || !assoc.id) fail('associate ' + JSON.stringify(assoc));

  const test = await call('test-associate', { id: assoc.id, key: b64(idKey.publicKey) });
  if (test.success !== 'true') fail('test-associate ' + JSON.stringify(test));

  const logins = await call('get-logins', { url: 'https://github.com/login', keys: [{ id: assoc.id, key: b64(idKey.publicKey) }] });
  if (logins.count !== 1 || logins.entries[0].password !== 's3cret') fail('get-logins ' + JSON.stringify(logins));

  const none = await call('get-logins', { url: 'https://nothing.example', keys: [{ id: assoc.id, key: b64(idKey.publicKey) }] });
  if (none.errorCode !== '15') fail('expected no logins ' + JSON.stringify(none));

  console.log('e2e ok:', JSON.stringify({ id: assoc.id, user: logins.entries[0].login }));
  process.exit(0);
});
sock.on('error', e => fail(e.message));
