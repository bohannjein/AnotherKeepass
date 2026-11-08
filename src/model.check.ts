// Self-check for the KDBX ↔ UI mapping. Run: node src/model.check.ts
import { matchesQuery, normalizeTotp, rawToItem, toRawFields } from './model.ts';

const eq = (a: unknown, b: unknown, msg: string) => {
  if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${msg}: ${JSON.stringify(a)} !== ${JSON.stringify(b)}`);
};

// bare secrets become KeePassXC-style URIs; spaces/dashes dropped, case normalized
const uri = normalizeTotp('jbsw y3dp-ehpk 3pxp', 'Git Hub');
eq(new URL(uri).searchParams.get('secret'), 'JBSWY3DPEHPK3PXP', 'secret cleaned');
eq(uri.startsWith('otpauth://totp/Git%20Hub?'), true, 'label encoded');
eq(normalizeTotp(' otpauth://totp/x?secret=ABC ', 'y'), 'otpauth://totp/x?secret=ABC', 'URI kept');
eq(normalizeTotp('', 'y'), '', 'empty stays empty');

// a stored secret that was never loaded is sent as null (backend keeps it)
const { fields, kinds } = toRawFields('T', '', [
  { key: 'password', value: '', kind: 'hidden', protected: true, raw: 'Password' },
  { key: 'password', value: 'new', kind: 'hidden', protected: true, raw: 'Password', loaded: true },
  { label: 'Born', value: '2000-01-01', kind: 'date' },
]);
eq(fields.find(f => f.name === 'Password')!.value, null, 'unloaded secret → null');
eq(fields.find(f => f.name === 'Password (2)')!.value, 'new', 'duplicate names get a suffix');
eq(kinds, { Born: 'date' }, 'only non-default kinds stored');

// foreign KeePass entry: type inferred, empty standard strings hidden for notes
const vault = { id: 'v', name: 'V', path: 'v', root: 'r', recycleBin: null, format: 'KDBX 4.1', folders: [], items: [] };
const note = rawToItem({
  id: '1', folder: 'r', trashed: false, tags: ['pinned', 'x'], customData: {}, attachments: [], modified: null, expires: null, history: [],
  fields: [
    { name: 'Title', value: 'Wifi', protected: false }, { name: 'Notes', value: 'pw: 123', protected: false },
    { name: 'UserName', value: '', protected: false }, { name: 'URL', value: '', protected: false },
  ],
}, vault);
eq([note.type, note.fields.length, note.pinned, note.tags, note.folder], ['note', 0, true, ['x'], undefined], 'note entry');

// search: plain fields, note and tags count, protected values don't
const found = (q: string) => matchesQuery({
  id: 's', vault: 'v', type: 'login', title: 'Mail', subtitle: 'jo@example.org', modified: '', tags: ['work'], note: 'Recovery codes in the safe',
  fields: [
    { key: 'username', value: 'jo@example.org', raw: 'UserName' }, { key: 'website', value: 'https://mail.example.org', kind: 'url', raw: 'URL' },
    { key: 'password', value: 'hunter2', kind: 'hidden', protected: true, raw: 'Password' }, { label: 'Department', value: 'Finance', raw: 'Department' },
  ],
}, q);
eq([found('mail.example'), found('finance'), found('department'), found('safe'), found('work'), found('example jo'), found('MAIL')], [true, true, true, true, true, true, true], 'search hits');
eq([found('hunter2'), found('mail hunter2'), found('nothing')], [false, false, false], 'search misses, passwords never match');

console.log('model ok');
