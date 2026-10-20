// Demo data for the browser preview (the desktop app only uses real .kdbx files).
// Registered as the demo backend's seed: opening "demo:<file>" loads these entries.
import { registerDemoSeed, type DemoVault, type RawItem } from './backend';
import { CD_KINDS, CD_TYPE, PINNED_TAG, toRawFields, type Attachment, type Field, type ItemType } from './model';

type DemoItem = {
  id: string; vault: string; type: ItemType; title: string; subtitle: string; fields: Field[];
  note?: string; attachments?: Attachment[]; pinned?: boolean; trashed?: boolean; modified: string; folder?: string;
};

const vaults = [
  { id: 'free', name: 'Freelance', file: 'freelance.kdbx', color: '--v-ochre', icon: 'work_history' },
  { id: 'personal', name: 'Personal', file: 'personal.kdbx', color: '--v-moss', icon: 'cottage' },
  { id: 'work', name: 'Work', file: 'work.kdbx', color: '--v-clay', icon: 'apartment', shared: true },
];

const folders = [
  { id: 'f-fin', vault: 'personal', name: 'Finance' },
  { id: 'f-dev', vault: 'personal', name: 'Developer' },
  { id: 'f-office', vault: 'work', name: 'Office' },
];

const items: DemoItem[] = [
  {
    id: '1', vault: 'work', type: 'card', title: 'Company card', subtitle: '1234 •••• •••• 1234', modified: '2026-08-02',
    fields: [
      { key: 'cardholder', value: 'J. Doe' },
      { key: 'number', value: '1234 5678 9012 1234', kind: 'hidden' },
      { key: 'expires', value: '09/28' },
      { key: 'cvc', value: '321', kind: 'hidden' },
    ],
  },
  {
    id: '2', vault: 'work', type: 'pin', title: 'Security door PIN', subtitle: 'Building B', folder: 'f-office', modified: '2026-07-14',
    fields: [{ key: 'pin', value: '1234', kind: 'hidden' }],
  },
  {
    id: '3', vault: 'work', type: 'login', title: 'Proton login', subtitle: 'team@proton.ch', pinned: true, modified: '2026-09-28',
    fields: [
      { key: 'username', value: 'team@proton.ch' },
      { key: 'password', value: 'Loam-Moss-47!', kind: 'hidden' },
      { key: 'website', value: 'https://mail.proton.me/', kind: 'url' },
    ],
  },
  {
    id: '4', vault: 'personal', type: 'login', title: 'GitHub', subtitle: 'earthling', folder: 'f-dev', pinned: true, modified: '2026-10-18',
    fields: [
      { key: 'username', value: 'earthling' },
      { key: 'password', value: 'Peat_Basalt_99', kind: 'hidden' },
      { key: 'website', value: 'https://github.com/', kind: 'url' },
      { key: 'totp', value: 'JBSWY3DPEHPK3PXP', kind: 'totp' },
      { label: 'Recovery email', value: 'backup@mail.de' },
      { label: 'Account created', value: '2019-04-12', kind: 'date' },
    ],
    note: 'Recovery codes are in the attachment.',
    attachments: [{ name: 'github-recovery-codes.txt', size: 412 }],
  },
  {
    id: '5', vault: 'personal', type: 'note', title: 'Home Wi-Fi', subtitle: 'SSID: Garden', modified: '2026-10-01',
    fields: [{ key: 'noteBody', value: 'SSID: Garden\nPassword: Compost-Heap-2026', kind: 'hidden' }],
  },
  {
    id: '6', vault: 'personal', type: 'login', title: 'Bank', subtitle: 'accountholder', folder: 'f-fin', modified: '2026-06-11',
    fields: [
      { key: 'username', value: 'accountholder' },
      { key: 'password', value: 'Clay&Pebble#5', kind: 'hidden' },
      { key: 'website', value: 'https://bank.example/', kind: 'url' },
    ],
  },
  {
    id: '7', vault: 'free', type: 'login', title: 'Client portal North', subtitle: 'freelancer@mail.de', modified: '2026-10-19',
    fields: [
      { key: 'username', value: 'freelancer@mail.de' },
      { key: 'password', value: 'Sandstone.88', kind: 'hidden' },
      { key: 'website', value: 'https://portal.example/', kind: 'url' },
    ],
  },
  {
    id: '8', vault: 'free', type: 'note', title: 'Invoice template', subtitle: 'Update IBAN', modified: '2026-05-03',
    fields: [{ key: 'noteBody', value: 'Update IBAN in template.' }],
  },
  {
    id: '10', vault: 'personal', type: 'identity', title: 'Me', subtitle: 'Jamie Doe', modified: '2026-09-02',
    fields: [
      { key: 'fullName', value: 'Jamie Doe' },
      { key: 'email', value: 'jamie@mail.de' },
      { key: 'phone', value: '+49 170 1234567' },
      { key: 'address', value: 'Lindenweg 4\n12345 Musterstadt' },
      { key: 'birthdate', value: '1990-05-17', kind: 'date' },
    ],
  },
  {
    id: '9', vault: 'personal', type: 'login', title: 'Old forum', subtitle: 'oldname', trashed: true, modified: '2026-03-03',
    fields: [{ key: 'username', value: 'oldname' }],
  },
];

export const DEMO_VAULTS = vaults.map(v => ({ path: 'demo:' + v.file, name: v.name, color: v.color, icon: v.icon }));

registerDemoSeed(path => {
  const v = vaults.find(x => 'demo:' + x.file === path);
  if (!v) return null;
  const root = 'root-' + v.id;
  const demo: DemoVault = {
    data: {
      id: path, name: v.name, path, root, recycleBin: 'bin-' + v.id, format: 'KDBX 4.1',
      folders: folders.filter(f => f.vault === v.id).map(f => ({ id: f.id, name: f.name, parent: null })),
      items: [],
    },
    secrets: new Map(), files: new Map(), snapshots: new Map(),
  };
  for (const i of items.filter(x => x.vault === v.id)) {
    const { fields, kinds } = toRawFields(i.title, i.note ?? '', i.fields.map(f => ({ ...f, protected: f.kind === 'hidden' || f.kind === 'totp' })));
    const secrets: Record<string, string> = {};
    const raw: RawItem = {
      id: i.id, folder: i.folder ?? root, trashed: !!i.trashed,
      fields: fields.map(f => { if (!f.protected) return f; secrets[f.name] = f.value ?? ''; return { ...f, value: null }; }),
      tags: i.pinned ? [PINNED_TAG] : [],
      customData: { [CD_TYPE]: i.type, ...(Object.keys(kinds).length ? { [CD_KINDS]: JSON.stringify(kinds) } : {}) },
      attachments: (i.attachments ?? []).map(a => ({ name: a.name, size: a.size })),
      modified: i.modified + 'T12:00:00', expires: i.id === '6' ? '2026-11-01T23:59:59' : null, history: [],
    };
    demo.secrets.set(i.id, secrets);
    demo.data.items.push(raw);
  }
  return demo;
});
