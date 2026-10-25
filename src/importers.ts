// Import from other password managers. Everything is parsed here in the UI process from a
// file the user picked; Rust only receives the finished entries (one write for all).
// Supported: Bitwarden (JSON/CSV), Proton Pass (ZIP/JSON/CSV), 1Password (1PUX/CSV),
// KeePassXC/Chrome/Edge/Firefox/LastPass and other CSV files (columns matched by name).
import type { ImportInput } from './backend';
import type { Strings } from './i18n';
import { CD_TYPE, DEFAULT_KIND, PINNED_TAG, normalizeTotp, toRawFields, type Field, type ItemType } from './model.ts';

export interface ImportEntry {
  type: ItemType;
  title: string;
  path: string[];
  fields: Field[];
  note: string;
  tags: string[];
  pinned?: boolean;
}
export interface ImportResult { source: string; entries: ImportEntry[]; skipped: number }

// ---------------------------------------------------------------- field helpers

const std = (key: keyof Strings, value: unknown): Field | null => {
  const v = str(value);
  if (!v) return null;
  const kind = DEFAULT_KIND[key];
  return { key, value: v, kind, protected: kind === 'hidden' || kind === 'totp' || undefined };
};
const custom = (label: unknown, value: unknown, kind?: Field['kind']): Field | null => {
  const v = str(value);
  return v ? { label: str(label) || 'Field', value: v, kind, protected: kind === 'hidden' || kind === 'totp' || undefined } : null;
};
const str = (v: unknown) => v == null ? '' : String(v).trim();
const compact = (fs: (Field | null)[]) => fs.filter((f): f is Field => !!f);
/** extra URLs the KeePassXC way (KP2A_URL, KP2A_URL_1 …), so the browser extension finds them */
const extraUrls = (urls: string[]) => urls.filter(Boolean).map((u, i) => custom(i ? `KP2A_URL_${i}` : 'KP2A_URL', u, 'url'));
const entry = (e: Omit<Partial<ImportEntry>, 'fields'> & { fields: (Field | null)[] }): ImportEntry => {
  const fields = compact(e.fields);
  const login = fields.some(f => f.key && ['username', 'password', 'website', 'totp'].includes(f.key));
  // exports can be damaged or hand-edited: everything that becomes text is forced to text here
  const texts = (a: unknown) => (Array.isArray(a) ? a : []).map(str).filter(Boolean);
  return { type: e.type ?? (login ? 'login' : 'note'), title: str(e.title), path: texts(e.path), fields, note: str(e.note), tags: texts(e.tags), pinned: e.pinned === true || undefined };
};

/** ImportEntry → what Rust stores (same mapping as the editor). */
export function toImportInput(e: ImportEntry): ImportInput {
  const fields = e.fields.map(f => f.kind === 'totp' ? { ...f, value: normalizeTotp(f.value, e.title) } : f);
  const { fields: raw, kinds } = toRawFields(e.title, e.note, fields);
  return {
    path: e.path,
    item: {
      id: null, folder: '', fields: raw,
      tags: [...e.tags.filter(t => t && t !== PINNED_TAG), ...(e.pinned ? [PINNED_TAG] : [])],
      customData: { [CD_TYPE]: e.type, ...(Object.keys(kinds).length ? { 'AnotherKeepass.Kinds': JSON.stringify(kinds) } : {}) },
      expires: null, keepAttachments: [], addAttachments: [],
    },
  };
}

// ---------------------------------------------------------------- CSV (RFC 4180)

export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [], cell = '', quoted = false;
  const s = text.replace(/^﻿/, '');
  const delim = detectDelimiter(s);
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quoted) {
      if (c === '"' && s[i + 1] === '"') { cell += '"'; i++; }
      else if (c === '"') quoted = false;
      else cell += c;
    } else if (c === '"') quoted = true;
    else if (c === delim) { row.push(cell); cell = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && s[i + 1] === '\n') i++;
      row.push(cell); cell = '';
      if (row.some(x => x !== '')) rows.push(row);
      row = [];
    } else cell += c;
  }
  row.push(cell);
  if (row.some(x => x !== '')) rows.push(row);
  return rows;
}
const detectDelimiter = (s: string) => {
  const head = s.slice(0, s.search(/\r?\n/) >>> 0 || s.length);
  return [',', ';', '\t'].map(d => [d, head.split(d).length] as const).sort((a, b) => b[1] - a[1])[0][0];
};

const norm = (h: string) => h.toLowerCase().replace(/[^a-z0-9]/g, '');
const COLS: Record<string, string[]> = {
  title: ['title', 'name', 'itemname', 'account', 'accountname'],
  username: ['username', 'loginusername', 'login', 'user', 'loginname', 'userid'],
  email: ['email', 'emailaddress'],
  password: ['password', 'loginpassword', 'pass'],
  url: ['url', 'uri', 'loginuri', 'website', 'web', 'urls', 'hostname'],
  notes: ['notes', 'note', 'extra', 'comments', 'comment'],
  totp: ['totp', 'otp', 'otpauth', 'logintotp', 'onetimepassword', 'twofactor', '2fa'],
  folder: ['group', 'folder', 'grouping', 'vault', 'path', 'collections'],
  tags: ['tags', 'tag', 'labels'],
  favorite: ['favorite', 'favourite', 'fav', 'starred'],
  type: ['type'],
  fields: ['fields'],
};
// bookkeeping columns of known exporters that aren't worth a custom field
const IGNORE = new Set(['icon', 'lastmodified', 'created', 'createtime', 'modifytime', 'modified', 'reprompt', 'archived',
  'httprealm', 'formactionorigin', 'guid', 'timecreated', 'timelastused', 'timepasswordchanged', 'id', 'loginfido2credentials']);

function fromCsv(text: string): ImportResult {
  const rows = parseCsv(text);
  if (rows.length < 2) throw new Error('empty');
  const header = rows[0].map(norm);
  const col = Object.fromEntries(Object.entries(COLS).map(([k, names]) => [k, header.findIndex(h => names.includes(h))])) as Record<keyof typeof COLS, number>;
  if (col.password < 0 && col.username < 0 && col.notes < 0) throw new Error('unknown_format');
  const known = new Set(Object.values(col).filter(i => i >= 0));
  const bitwarden = header.includes('loginuri');
  const proton = header.includes('createtime') && header.includes('vault');
  const keepassxc = header.includes('group') && header.includes('lastmodified');
  const source = bitwarden ? 'Bitwarden (CSV)' : proton ? 'Proton Pass (CSV)' : keepassxc ? 'KeePassXC (CSV)' : header.includes('otpauth') ? '1Password (CSV)' : 'CSV';
  const entries = rows.slice(1).map(r => {
    const at = (k: keyof typeof COLS) => col[k] >= 0 ? (r[col[k]] ?? '').trim() : '';
    let path = at('folder').split(/[/\\]/).map(s => s.trim()).filter(Boolean);
    if (keepassxc && path[0] === 'Root') path = path.slice(1); // KeePassXC writes the root group name
    const username = at('username') || at('email');
    const extra = header.map((h, i) => known.has(i) || IGNORE.has(h) || !r[i]?.trim() ? null : custom(rows[0][i].trim(), r[i]));
    // Bitwarden CSV: "fields" column holds "name: value" lines
    const listed = at('fields').split('\n').filter(Boolean).map(l => { const m = l.match(/^([^:]+):\s?(.*)$/); return m ? custom(m[1], m[2]) : custom('Field', l); });
    const isNote = /^(note|securenote|2)$/i.test(at('type'));
    return entry({
      type: isNote ? 'note' : undefined,
      title: at('title') || hostOf(at('url')) || username,
      path,
      fields: [
        std('username', username),
        at('email') && at('username') ? custom('Email', at('email')) : null,
        std('password', at('password')),
        ...(at('url') ? [std('website', at('url').split(/[\s,]+/)[0]), ...extraUrls(at('url').split(/[\s,]+/).slice(1))] : []),
        std('totp', at('totp')),
        ...listed, ...extra,
      ],
      note: at('notes'),
      tags: at('tags').split(/[,;]/).map(s => s.trim()).filter(Boolean),
      pinned: /^(1|true|yes|x)$/i.test(at('favorite')),
    });
  });
  return { source, entries, skipped: 0 };
}
const hostOf = (u: string) => { try { return new URL(u.includes('://') ? u : 'https://' + u).hostname.replace(/^www\./, ''); } catch { return ''; } };

// ---------------------------------------------------------------- Bitwarden JSON

/* eslint-disable @typescript-eslint/no-explicit-any */
function fromBitwarden(j: any): ImportResult {
  if (j.encrypted) throw new Error('encrypted');
  const folders = new Map<string, string>((j.folders ?? []).map((f: any) => [f.id, f.name]));
  const collections = new Map<string, string>((j.collections ?? []).map((c: any) => [c.id, c.name]));
  const entries = (j.items ?? []).map((it: any): ImportEntry => {
    const path = it.folderId ? folders.get(it.folderId)?.split('/') ?? []
      : it.collectionIds?.length ? collections.get(it.collectionIds[0])?.split('/') ?? [] : [];
    const extra = (it.fields ?? []).map((f: any) => custom(f.name, f.type === 2 ? (f.value === 'true' ? '✓' : '✗') : f.value, f.type === 1 ? 'hidden' : undefined));
    const base = { title: it.name, path, note: it.notes ?? '', pinned: !!it.favorite };
    switch (it.type) {
      case 1: {
        const uris = (it.login?.uris ?? []).map((u: any) => u.uri).filter(Boolean);
        return entry({ ...base, type: 'login', fields: [
          std('username', it.login?.username), std('password', it.login?.password), std('website', uris[0]),
          ...extraUrls(uris.slice(1)), std('totp', it.login?.totp), ...extra] });
      }
      case 3: {
        const c = it.card ?? {};
        return entry({ ...base, type: 'card', fields: [
          std('cardholder', c.cardholderName), std('number', c.number),
          std('expires', c.expMonth || c.expYear ? `${String(c.expMonth ?? '').padStart(2, '0')}/${c.expYear ?? ''}` : ''),
          std('cvc', c.code), custom('Brand', c.brand), ...extra] });
      }
      case 4: {
        const d = it.identity ?? {};
        const name = [d.title, d.firstName, d.middleName, d.lastName].filter(Boolean).join(' ');
        const address = [d.address1, d.address2, d.address3, [d.postalCode, d.city].filter(Boolean).join(' '), d.state, d.country].filter(Boolean).join('\n');
        return entry({ ...base, type: 'identity', fields: [
          std('fullName', name), std('email', d.email), std('phone', d.phone), std('address', address),
          custom('Company', d.company), custom('Username', d.username), custom('SSN', d.ssn, 'hidden'),
          custom('Passport number', d.passportNumber, 'hidden'), custom('License number', d.licenseNumber, 'hidden'), ...extra] });
      }
      case 5: {
        const k = it.sshKey ?? {};
        return entry({ ...base, type: 'other', fields: [custom('Private key', k.privateKey, 'hidden'), custom('Public key', k.publicKey), custom('Fingerprint', k.keyFingerprint), ...extra] });
      }
      default: return entry({ ...base, type: 'note', fields: extra });
    }
  });
  return { source: 'Bitwarden', entries, skipped: 0 };
}

// ---------------------------------------------------------------- Proton Pass JSON (inside the export ZIP)

function fromProton(j: any): ImportResult {
  if (j.encrypted) throw new Error('encrypted');
  let skipped = 0;
  const entries: ImportEntry[] = [];
  for (const vault of Object.values<any>(j.vaults ?? {})) {
    for (const it of vault.items ?? []) {
      if (it.state === 2) { skipped++; continue; } // in Proton's trash
      const d = it.data ?? {}, c = d.content ?? {};
      const extra = (d.extraFields ?? []).map((f: any) => custom(f.fieldName, f.data?.content ?? f.data?.totpUri, f.type === 'hidden' ? 'hidden' : f.type === 'totp' ? 'totp' : undefined));
      const base = { title: d.metadata?.name ?? '', path: [vault.name].filter(Boolean), note: d.metadata?.note ?? '', pinned: !!it.pinned };
      switch (d.type) {
        case 'login': {
          const user = c.itemUsername || c.username || c.itemEmail;
          entries.push(entry({ ...base, type: 'login', fields: [
            std('username', user), c.itemUsername && c.itemEmail ? custom('Email', c.itemEmail) : null,
            std('password', c.password), std('website', c.urls?.[0]), ...extraUrls(c.urls?.slice(1) ?? []),
            std('totp', c.totpUri), ...extra] }));
          break;
        }
        case 'alias':
          entries.push(entry({ ...base, type: 'login', fields: [std('username', it.aliasEmail), ...extra] }));
          break;
        case 'creditCard':
          entries.push(entry({ ...base, type: 'card', fields: [
            std('cardholder', c.cardholderName), std('number', c.number),
            std('expires', /^\d{4}-\d{2}$/.test(c.expirationDate ?? '') ? `${c.expirationDate.slice(5)}/${c.expirationDate.slice(0, 4)}` : c.expirationDate),
            std('cvc', c.verificationCode), std('pin', c.pin), ...extra] }));
          break;
        case 'identity': {
          const address = [c.streetAddress, [c.zipOrPostalCode, c.city].filter(Boolean).join(' '), c.stateOrProvince, c.countryOrRegion].filter(Boolean).join('\n');
          const known = new Set(['fullName', 'email', 'phoneNumber', 'streetAddress', 'zipOrPostalCode', 'city', 'stateOrProvince', 'countryOrRegion', 'birthdate',
            'extraPersonalDetails', 'extraAddressDetails', 'extraContactDetails', 'extraWorkDetails', 'extraSections']);
          const rest = Object.entries(c).filter(([k, v]) => !known.has(k) && typeof v === 'string').map(([k, v]) => custom(k.replace(/([A-Z])/g, ' $1').replace(/^./, s => s.toUpperCase()), v));
          entries.push(entry({ ...base, type: 'identity', fields: [
            std('fullName', c.fullName), std('email', c.email), std('phone', c.phoneNumber), std('address', address), std('birthdate', c.birthdate), ...rest, ...extra] }));
          break;
        }
        case 'sshKey':
          entries.push(entry({ ...base, type: 'other', fields: [custom('Private key', c.privateKey, 'hidden'), custom('Public key', c.publicKey), ...extra] }));
          break;
        case 'wifi':
          entries.push(entry({ ...base, type: 'other', fields: [custom('SSID', c.ssid), std('password', c.password), ...extra] }));
          break;
        default:
          entries.push(entry({ ...base, type: 'note', fields: extra }));
      }
    }
  }
  return { source: 'Proton Pass', entries, skipped };
}

// ---------------------------------------------------------------- 1Password 1PUX (export.data inside the ZIP)

function from1Password(j: any): ImportResult {
  let skipped = 0;
  const entries: ImportEntry[] = [];
  for (const account of j.accounts ?? []) {
    for (const vault of account.vaults ?? []) {
      for (const it of vault.items ?? []) {
        if (it.state === 'archived' || it.trashed) { skipped++; continue; }
        const o = it.overview ?? {}, d = it.details ?? {};
        const login = d.loginFields ?? [];
        const designated = (k: string) => login.find((f: any) => f.designation === k)?.value;
        const urls = [o.url, ...(o.urls ?? []).map((u: any) => u.url)].filter((u, i, a) => u && a.indexOf(u) === i);
        const sectionFields = (d.sections ?? []).flatMap((s: any) => (s.fields ?? []).map((f: any) => {
          const v = f.value ?? {};
          if (v.totp) return std('totp', v.totp);
          if (v.concealed != null) return custom(f.title || s.title, v.concealed, 'hidden');
          if (v.date) return custom(f.title, new Date(v.date * 1000).toISOString().slice(0, 10), 'date');
          if (v.monthYear) return custom(f.title, `${String(v.monthYear % 100).padStart(2, '0')}/${Math.floor(v.monthYear / 100)}`);
          const plain = v.string ?? v.email?.email_address ?? v.email ?? v.phone ?? v.url ?? v.creditCardNumber ?? v.creditCardType ?? v.menu;
          return custom(f.title || s.title, typeof plain === 'object' ? '' : plain, v.url ? 'url' : undefined);
        }));
        const cat = it.categoryUuid;
        entries.push(entry({
          type: cat === '001' || cat === '005' ? 'login' : cat === '002' ? 'card' : cat === '004' ? 'identity' : cat === '003' ? 'note' : undefined,
          title: o.title ?? '', path: [vault.attrs?.name].filter(Boolean), note: d.notesPlain ?? '',
          tags: o.tags ?? [], pinned: (it.favIndex ?? 0) > 0,
          fields: [std('username', designated('username')), std('password', designated('password') ?? d.password),
            std('website', urls[0]), ...extraUrls(urls.slice(1)), ...sectionFields],
        }));
      }
    }
  }
  return { source: '1Password', entries, skipped };
}
/* eslint-enable @typescript-eslint/no-explicit-any */

// ---------------------------------------------------------------- ZIP (stored/deflate, enough for export files)

export async function unzip(buf: ArrayBuffer): Promise<Map<string, Uint8Array>> {
  const b = new Uint8Array(buf), dv = new DataView(buf);
  let eocd = -1;
  for (let i = b.length - 22; i >= Math.max(0, b.length - 65_557); i--) if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new Error('unknown_format');
  const out = new Map<string, Uint8Array>();
  let p = dv.getUint32(eocd + 16, true);
  for (let n = dv.getUint16(eocd + 10, true); n > 0; n--) {
    const method = dv.getUint16(p + 10, true), size = dv.getUint32(p + 20, true);
    const nameLen = dv.getUint16(p + 28, true), extraLen = dv.getUint16(p + 30, true), commentLen = dv.getUint16(p + 32, true);
    const local = dv.getUint32(p + 42, true);
    const name = new TextDecoder().decode(b.subarray(p + 46, p + 46 + nameLen));
    const start = local + 30 + dv.getUint16(local + 26, true) + dv.getUint16(local + 28, true);
    const data = b.subarray(start, start + size);
    if (method === 0) out.set(name, data);
    else if (method === 8) out.set(name, new Uint8Array(await new Response(new Blob([data.slice()]).stream().pipeThrough(new DecompressionStream('deflate-raw'))).arrayBuffer()));
    p += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

// ---------------------------------------------------------------- entry point

/** Detects the format from name + content. Errors: 'encrypted', 'unknown_format', 'empty'. */
export async function parseImport(name: string, bytes: ArrayBuffer): Promise<ImportResult> {
  const head = new Uint8Array(bytes.slice(0, 4));
  if (head[0] === 0x50 && head[1] === 0x4b) {
    const files = await unzip(bytes);
    const find = (re: RegExp) => [...files.entries()].find(([n]) => re.test(n))?.[1];
    const text = (d: Uint8Array) => new TextDecoder().decode(d);
    const onePux = find(/(^|\/)export\.data$/);
    if (onePux) return from1Password(JSON.parse(text(onePux)));
    const data = find(/(^|\/)data\.json$/);
    if (data) return fromProton(JSON.parse(text(data)));
    if (find(/\.pgp$/)) throw new Error('encrypted');
    const inner = [...files.entries()].find(([n]) => /\.(json|csv)$/i.test(n));
    if (inner) return parseImport(inner[0], inner[1].slice().buffer);
    throw new Error('unknown_format');
  }
  const text = new TextDecoder().decode(bytes).replace(/^﻿/, '');
  if (/^\s*[{[]/.test(text)) {
    const j = JSON.parse(text);
    if (j.vaults && !Array.isArray(j.vaults)) return fromProton(j);
    if (Array.isArray(j.accounts)) return from1Password(j);
    if (Array.isArray(j.items) || j.encrypted) return fromBitwarden(j);
    throw new Error('unknown_format');
  }
  if (!/\.(csv|txt)$/i.test(name) && !text.includes(',') && !text.includes(';')) throw new Error('unknown_format');
  return fromCsv(text);
}
