// UI model and its mapping to KDBX entries.
// KDBX knows only strings: Title/UserName/Password/URL/Notes plus custom strings.
// Our item type and field kinds live in entry custom data, which KeePassXC keeps untouched.
import type { ItemInput, RawField, RawItem, VaultData } from './backend';
import type { Strings } from './i18n';

export type ItemType = 'login' | 'card' | 'note' | 'pin' | 'identity' | 'other';
export type FieldKind = 'text' | 'hidden' | 'totp' | 'date' | 'url';

export interface Field {
  key?: keyof Strings;   // built-in field (translated label)
  label?: string;        // custom field (user label)
  value: string;         // '' for protected values not loaded yet
  kind?: FieldKind;      // default 'text'
  protected?: boolean;   // stored as KDBX protected string
  raw?: string;          // KDBX string name, set for stored fields
  loaded?: boolean;      // protected value fetched from the backend (edit mode)
}

export interface Attachment { name: string; size: number; url?: string; file?: File }

export interface Item {
  id: string;
  vault: string;
  type: ItemType;
  title: string;
  subtitle: string;
  fields: Field[];
  note?: string;
  attachments?: Attachment[];
  pinned?: boolean;
  trashed?: boolean;
  modified: string;
  folder?: string;
  expires?: string | null; // YYYY-MM-DD
  history?: string[];
  tags?: string[];
  /** data: URL of the KeePass custom icon (website favicon) */
  icon?: string;
}

export interface Folder { id: string; vault: string; name: string; parent?: string | null; share?: 'sync' | 'export' | 'import' | null }

/** A vault in the sidebar: open (data loaded) or locked (only remembered). */
export interface VaultInfo { id: string; name: string; file: string; color: string; icon: string; locked: boolean }

export const CD_TYPE = 'AnotherKeepass.Type';
export const CD_KINDS = 'AnotherKeepass.Kinds';
export const PINNED_TAG = 'pinned';

// built-in field ↔ KDBX string name (English names stay stable across UI languages)
const NAME: Partial<Record<keyof Strings, string>> = {
  username: 'UserName', password: 'Password', website: 'URL', totp: 'otp',
  cardholder: 'Cardholder', number: 'Card number', expires: 'Card expiry', cvc: 'CVC', pin: 'PIN',
  fullName: 'Full name', email: 'Email', phone: 'Phone', address: 'Address', birthdate: 'Date of birth',
  noteBody: 'Note',
};
const KEY_BY_NAME = Object.fromEntries(Object.entries(NAME).map(([k, v]) => [v, k])) as Record<string, keyof Strings>;
export const DEFAULT_KIND: Partial<Record<keyof Strings, FieldKind>> = {
  password: 'hidden', number: 'hidden', cvc: 'hidden', pin: 'hidden', website: 'url', totp: 'totp', birthdate: 'date',
};
const ORDER = Object.keys(NAME);

export const fieldRawName = (f: Field) => f.raw ?? (f.key ? NAME[f.key] ?? f.key : f.label ?? '');
const isProtectedKind = (k?: FieldKind) => k === 'hidden' || k === 'totp';

/** first plain, non-empty field value shown as list subtitle */
export const subtitleOf = (fields: Field[]) =>
  fields.find(f => (!f.kind || f.kind === 'text') && !f.protected && f.value)?.value.split('\n')[0] ?? '';

function inferType(names: Set<string>, note: string): ItemType {
  if (names.has('Card number')) return 'card';
  if (names.has('Full name')) return 'identity';
  if (['UserName', 'Password', 'URL', 'otp'].some(n => names.has(n))) return 'login';
  return note ? 'note' : 'other';
}

/** PNG/ICO/SVG bytes (base64) → data: URL with the right type */
export function iconUrl(b64: string) {
  const type = b64.startsWith('iVBOR') ? 'image/png' : b64.startsWith('AAABAA') ? 'image/x-icon' : b64.startsWith('PHN2') || b64.startsWith('PD94') ? 'image/svg+xml' : 'image/png';
  return `data:${type};base64,${b64}`;
}

export function rawToItem(raw: RawItem, v: VaultData): Item {
  let title = '', note = '';
  let kinds: Record<string, FieldKind> = {};
  try { kinds = JSON.parse(raw.customData[CD_KINDS] ?? '{}'); } catch { /* foreign/old data */ }
  const fields: Field[] = [];
  const nonEmpty = new Set<string>();
  for (const f of raw.fields) {
    if (f.name === 'Title') { title = f.value ?? ''; continue; }
    if (f.name === 'Notes') { note = f.value ?? ''; continue; }
    if (f.name.startsWith('KPEX_PASSKEY') || f.name.startsWith('KPXC_PASSKEY')) continue; // passkey data, see Rust apply_item
    if (f.protected || f.value) nonEmpty.add(f.name);
    const key = KEY_BY_NAME[f.name];
    const kind = kinds[f.name] ?? (key && DEFAULT_KIND[key]) ?? (f.protected ? 'hidden' : 'text');
    fields.push({ key, label: key ? undefined : f.name, value: f.value ?? '', kind: kind === 'text' ? undefined : kind, protected: f.protected, raw: f.name });
  }
  const rank = (f: Field) => f.key ? ORDER.indexOf(f.key) : ORDER.length;
  fields.sort((a, b) => rank(a) - rank(b) || fieldRawName(a).localeCompare(fieldRawName(b)));
  const type = (raw.customData[CD_TYPE] as ItemType) || inferType(nonEmpty, note);
  // standard KeePass strings exist (empty) on every entry; hide them where the type doesn't use them
  const shown = type === 'login' ? fields : fields.filter(f => f.protected || f.value || !['UserName', 'Password', 'URL'].includes(f.raw!));
  return {
    id: raw.id,
    vault: v.id,
    type,
    title,
    subtitle: subtitleOf(shown),
    fields: shown,
    note,
    attachments: raw.attachments,
    pinned: raw.tags.includes(PINNED_TAG),
    tags: raw.tags.filter(t => t !== PINNED_TAG),
    trashed: raw.trashed,
    modified: raw.modified?.slice(0, 10) ?? '',
    folder: raw.folder === v.root ? undefined : raw.folder,
    expires: raw.expires?.slice(0, 10) ?? null,
    history: raw.history,
    icon: raw.icon && v.icons?.[raw.icon] ? iconUrl(v.icons[raw.icon]) : undefined,
  };
}

/** Field list → KDBX strings + kinds that can't be derived from defaults. */
export function toRawFields(title: string, note: string, fields: Field[]): { fields: RawField[]; kinds: Record<string, FieldKind> } {
  const kinds: Record<string, FieldKind> = {};
  const out: RawField[] = [
    { name: 'Title', value: title, protected: false },
    { name: 'Notes', value: note, protected: false },
  ];
  const used = new Set(['Title', 'Notes']);
  for (const f of fields) {
    let name = fieldRawName(f).trim() || 'Field';
    for (let n = 2; used.has(name); n++) name = `${fieldRawName(f).trim() || 'Field'} (${n})`; // KDBX names are unique keys
    used.add(name);
    const kind = f.kind ?? 'text';
    const defaultKind = (f.key && DEFAULT_KIND[f.key]) ?? 'text';
    if (kind !== defaultKind && !(kind === 'hidden' && f.protected)) kinds[name] = kind;
    // a stored secret that was never loaded is sent as null = keep the stored value
    const keep = f.protected && f.raw && !f.loaded;
    out.push({ name, value: keep ? null : f.value, protected: f.protected ?? isProtectedKind(kind) });
  }
  return { fields: out, kinds };
}

export interface Draft { title: string; folder: string; fields: Field[]; note: string; attachments: Attachment[]; expires: string | null; tags: string[] }

/** Store TOTP like KeePassXC: always an otpauth:// URI, even when the user pasted a bare secret. */
export function normalizeTotp(value: string, label: string): string {
  const v = value.trim();
  if (!v || v.toLowerCase().startsWith('otpauth://')) return v;
  const secret = v.replace(/[\s-]/g, '').toUpperCase();
  return `otpauth://totp/${encodeURIComponent(label || 'AnotherKeepass')}?secret=${secret}&period=30&digits=6&issuer=AnotherKeepass`;
}

const toBase64 = async (file: File) => {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
};

export async function draftToInput(item: Item, d: Draft, root: string): Promise<ItemInput> {
  const filled = d.fields
    .filter(f => f.key || f.label || f.value)
    .map(f => f.kind === 'totp' && (!f.protected || f.loaded || !f.raw) ? { ...f, value: normalizeTotp(f.value, d.title) } : f);
  const { fields, kinds } = toRawFields(d.title, d.note, filled);
  return {
    id: item.id.startsWith('new:') ? null : item.id,
    folder: d.folder || root,
    fields,
    tags: [...d.tags.filter(t => t !== PINNED_TAG), ...(item.pinned ? [PINNED_TAG] : [])],
    customData: { [CD_TYPE]: item.type, ...(Object.keys(kinds).length ? { [CD_KINDS]: JSON.stringify(kinds) } : {}) },
    expires: d.expires,
    keepAttachments: d.attachments.filter(a => !a.file).map(a => a.name),
    addAttachments: await Promise.all(d.attachments.filter(a => a.file).map(async a => ({ name: a.name, base64: await toBase64(a.file!) }))),
  };
}
