// Vault backend: real .kdbx files through Tauri in the desktop app, an in-memory
// demo (seeded from mock.ts) in the browser preview. Same API for both.
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { totp } from './totp';

export interface RawField { name: string; value: string | null; protected: boolean }
export interface RawItem {
  id: string;
  folder: string;
  trashed: boolean;
  fields: RawField[];
  tags: string[];
  customData: Record<string, string>;
  attachments: { name: string; size: number }[];
  modified: string | null;
  expires: string | null;
  history: string[];
}
export interface VaultData {
  id: string;
  name: string;
  path: string;
  root: string;
  recycleBin: string | null;
  format: string; // "KDBX 3.1" is upgraded to KDBX 4 on the next save (backup kept)
  folders: { id: string; name: string; parent: string | null }[];
  items: RawItem[];
}
export interface ItemInput {
  id: string | null;
  folder: string;
  fields: RawField[];
  tags: string[];
  customData: Record<string, string>;
  expires: string | null;
  keepAttachments: string[];
  addAttachments: { name: string; base64: string }[];
}
export interface ImportInput { path: string[]; item: ItemInput }
export interface Health { vault: string; id: string; bits: number; weak: boolean; reused: number; ageDays: number; old: boolean; expired: boolean }
export interface Totp { code: string; remaining: number; period: number }
export interface AutoTypeCandidate { vault: string; id: string; title: string; username: string; sequence: string }
export interface AutoTypePick { windowTitle: string; candidates: AutoTypeCandidate[] }
export type BrowserAsk =
  | { id: number; kind: 'associate' }
  | { id: number; kind: 'access'; host: string; entries: { vault: string; uuid: string; title: string; username: string }[] }
  | { id: number; kind: 'update'; title: string; username: string };

export interface Backend {
  desktop: boolean;
  create(path: string, name: string, password: string, keyfile?: string): Promise<VaultData>;
  open(path: string, password: string, keyfile?: string): Promise<VaultData>;
  close(id: string): Promise<void>;
  /** which remembered vault files still exist */
  pathsExist(paths: string[]): Promise<boolean[]>;
  lockAll(): Promise<void>;
  changeKey(id: string, password: string, keyfile?: string): Promise<void>;
  rename(id: string, name: string): Promise<VaultData>;
  save(vault: string, item: ItemInput): Promise<[string, VaultData]>;
  /** many new entries, folders by name path below parent (null = root); one file write */
  importItems(vault: string, parent: string | null, items: ImportInput[]): Promise<[number, VaultData]>;
  secrets(vault: string, id: string): Promise<Record<string, string>>;
  /** password health of all open vaults (flags only, passwords stay in the backend) */
  healthReport(): Promise<Health[]>;
  /** HIBP k-anonymity: hash prefixes to ask for, then entry id → breach count */
  breachPrefixes(): Promise<string[]>;
  breachMatch(ranges: Record<string, string>): Promise<Record<string, number>>;
  totp(vault: string, id: string, field: string): Promise<Totp>;
  copy(vault: string, id: string, field: string, asTotp: boolean, clearAfter: number | null): Promise<void>;
  move(vault: string, id: string, folder: string | null): Promise<VaultData>;
  moveToVault(src: string, id: string, dst: string, folder: string | null): Promise<[VaultData, VaultData]>;
  duplicate(vault: string, id: string, suffix: string): Promise<[string, VaultData]>;
  copyText(text: string, clearAfter: number | null): Promise<void>;
  readText(): Promise<string>;
  /** desktop options mirrored to Rust; returns problems (e.g. invalid shortcut) */
  desktopApply(prefs: Record<string, unknown>): Promise<string[]>;
  windowMinimize(): Promise<void>;
  /** minimizes only if the browser/Auto-Type asked for the unlock */
  windowAfterUnlock(): Promise<void>;
  autotypePerform(vault: string, id: string, sequence: string | null): Promise<void>;
  autotypeEntry(vault: string, id: string): Promise<void>;
  /** desktop events from Rust (lock, auto-type); no-op in the browser demo */
  on<T>(event: string, cb: (payload: T) => void): () => void;
  /** answer a browser-extension question (null = deny) */
  browserAnswer(id: number, answer: unknown): Promise<void>;
  /** vault the browser extension talks to */
  browserSetActive(vault: string | null): Promise<void>;
  /** write to the app log file (desktop) / console (browser) */
  log(level: 'info' | 'warn' | 'error', message: string): void;
  trash(vault: string, id: string): Promise<VaultData>;
  restore(vault: string, id: string): Promise<VaultData>;
  remove(vault: string, id: string): Promise<VaultData>;
  emptyTrash(vault: string): Promise<VaultData>;
  historyRestore(vault: string, id: string, index: number): Promise<VaultData>;
  attachmentSave(vault: string, id: string, name: string, dest: string): Promise<void>;
  folderCreate(vault: string, parent: string | null, name: string): Promise<VaultData>;
  folderRename(vault: string, id: string, name: string): Promise<VaultData>;
  folderTrash(vault: string, id: string): Promise<VaultData>;
}

const desktop: Backend = {
  desktop: true,
  create: (path, name, password, keyfile) => invoke('vault_create', { path, name, password, keyfile }),
  open: (path, password, keyfile) => invoke('vault_open', { path, password, keyfile }),
  close: id => invoke('vault_close', { id }),
  pathsExist: paths => invoke('paths_exist', { paths }),
  lockAll: () => invoke('vault_lock_all'),
  changeKey: (id, password, keyfile) => invoke('vault_change_key', { id, password, keyfile }),
  rename: (id, name) => invoke('vault_rename', { id, name }),
  save: (vault, item) => invoke('entry_save', { vault, item }),
  importItems: (vault, parent, items) => invoke('entry_import', { vault, parent, items }),
  secrets: (vault, id) => invoke('entry_secrets', { vault, id }),
  healthReport: () => invoke('health_report'),
  breachPrefixes: () => invoke('health_breach_prefixes'),
  breachMatch: ranges => invoke('health_breach_match', { ranges }),
  totp: (vault, id, field) => invoke('entry_totp', { vault, id, field }),
  copy: (vault, id, field, asTotp, clearAfter) => invoke('entry_copy', { vault, id, field, asTotp, clearAfter }),
  move: (vault, id, folder) => invoke('entry_move', { vault, id, folder }),
  moveToVault: (src, id, dst, folder) => invoke('entry_move_to_vault', { src, id, dst, folder }),
  duplicate: (vault, id, suffix) => invoke('entry_duplicate', { vault, id, suffix }),
  copyText: (text, clearAfter) => invoke('clipboard_copy_text', { text, clearAfter }),
  readText: () => invoke('clipboard_read_text'),
  desktopApply: prefs => invoke('desktop_apply', { prefs }),
  windowMinimize: () => invoke('window_minimize'),
  windowAfterUnlock: () => invoke('window_after_unlock'),
  autotypePerform: (vault, id, sequence) => invoke('autotype_perform', { vault, id, sequence }),
  autotypeEntry: (vault, id) => invoke('autotype_entry', { vault, id }),
  browserAnswer: (id, answer) => invoke('browser_answer', { id, answer }),
  browserSetActive: vault => invoke('browser_set_active', { vault }),
  log: (level, message) => { invoke('ui_log', { level, message }).catch(() => {}); },
  on: (event, cb) => { const p = listen(event, e => cb(e.payload as never)); return () => { p.then(f => f()); }; },
  trash: (vault, id) => invoke('entry_trash', { vault, id }),
  restore: (vault, id) => invoke('entry_restore', { vault, id }),
  remove: (vault, id) => invoke('entry_delete', { vault, id }),
  emptyTrash: vault => invoke('trash_empty', { vault }),
  historyRestore: (vault, id, index) => invoke('entry_history_restore', { vault, id, index }),
  attachmentSave: (vault, id, name, dest) => invoke('attachment_save', { vault, id, name, dest }),
  folderCreate: (vault, parent, name) => invoke('folder_create', { vault, parent, name }),
  folderRename: (vault, id, name) => invoke('folder_rename', { vault, id, name }),
  folderTrash: (vault, id) => invoke('folder_trash', { vault, id }),
};

// ---------------------------------------------------------------- browser demo

type DemoVault = { data: VaultData; secrets: Map<string, Record<string, string>>; files: Map<string, Uint8Array>; snapshots: Map<string, RawItem[]> };
const demoVaults = new Map<string, DemoVault>();
let seed: ((path: string) => DemoVault | null) | null = null;
/** mock.ts registers its demo files here, so this module stays free of demo data */
export const registerDemoSeed = (fn: (path: string) => DemoVault | null) => { seed = fn; };
export type { DemoVault };

const clone = <T,>(x: T): T => structuredClone(x);
const now = () => new Date().toISOString().slice(0, 19);
const get = (id: string) => {
  const v = demoVaults.get(id);
  if (!v) throw new Error('vault_closed');
  return v;
};
const item = (v: DemoVault, id: string) => {
  const i = v.data.items.find(x => x.id === id);
  if (!i) throw new Error('not_found');
  return i;
};
const out = (v: DemoVault) => clone(v.data);
let clipTimer: number | undefined;

const demo: Backend = {
  desktop: false,
  async create(path, name) {
    const root = crypto.randomUUID(), bin = crypto.randomUUID();
    const v: DemoVault = {
      data: { id: path, name, path, root, recycleBin: bin, format: 'KDBX 4.1', folders: [], items: [] },
      secrets: new Map(), files: new Map(), snapshots: new Map(),
    };
    demoVaults.set(path, v);
    return out(v);
  },
  async open(path, password) {
    if (!password) throw new Error('empty_key');
    const v = demoVaults.get(path) ?? seed?.(path);
    if (!v) throw new Error('io:not found');
    demoVaults.set(path, v);
    return out(v);
  },
  async close(id) { demoVaults.delete(id); },
  async pathsExist(paths) { return paths.map(() => true); },
  async lockAll() { demoVaults.clear(); },
  async changeKey() {},
  async rename(id, name) { const v = get(id); v.data.name = name; return out(v); },
  async save(vault, input) {
    const v = get(vault);
    const id = input.id ?? crypto.randomUUID();
    const prev = v.data.items.find(i => i.id === id);
    const oldSecrets = v.secrets.get(id) ?? {};
    if (prev) v.snapshots.set(id, [clone(prev), ...(v.snapshots.get(id) ?? [])].slice(0, 10));
    const secrets: Record<string, string> = {};
    const fields = input.fields.map(f => {
      if (!f.protected) return f;
      secrets[f.name] = f.value ?? oldSecrets[f.name] ?? '';
      return { ...f, value: null };
    });
    v.secrets.set(id, secrets);
    for (const a of input.addAttachments) v.files.set(id + '/' + a.name, Uint8Array.from(atob(a.base64), c => c.charCodeAt(0)));
    const next: RawItem = {
      id, folder: input.folder, trashed: false, fields, tags: input.tags, customData: input.customData,
      attachments: [
        ...(prev?.attachments ?? []).filter(a => input.keepAttachments.includes(a.name)),
        ...input.addAttachments.map(a => ({ name: a.name, size: Math.floor(a.base64.length * 3 / 4) })),
      ],
      modified: now(), expires: input.expires ? input.expires.slice(0, 10) + 'T23:59:59' : null,
      history: (v.snapshots.get(id) ?? []).map(s => s.modified ?? ''),
    };
    v.data.items = prev ? v.data.items.map(i => i.id === id ? next : i) : [...v.data.items, next];
    return [id, out(v)];
  },
  async importItems(vault, parent, items) {
    const v = get(vault);
    for (const { path, item: input } of items) {
      let cur = parent;
      for (const name of path.map(n => n.trim()).filter(Boolean)) {
        let f = v.data.folders.find(x => x.name === name && x.parent === cur);
        if (!f) v.data.folders.push(f = { id: crypto.randomUUID(), name, parent: cur });
        cur = f.id;
      }
      await demo.save(vault, { ...input, id: null, folder: cur ?? v.data.root });
    }
    return [items.length, out(v)];
  },
  async healthReport() {
    const rows: (Health & { pw: string })[] = [];
    for (const [vid, v] of demoVaults) for (const i of v.data.items) {
      const pw = v.secrets.get(i.id)?.Password ?? '';
      if (!pw || i.trashed) continue;
      const pool = (/[a-z]/.test(pw) ? 26 : 0) + (/[A-Z]/.test(pw) ? 26 : 0) + (/\d/.test(pw) ? 10 : 0) + (/[^a-zA-Z\d]/.test(pw) ? 33 : 0);
      const bits = Math.round(pw.length * Math.log2(pool || 1));
      const ageDays = Math.floor((Date.now() - Date.parse(i.modified ?? '')) / 86_400_000) || 0;
      rows.push({ pw, vault: vid, id: i.id, bits, weak: bits < 50, reused: 0, ageDays, old: ageDays > 365, expired: !!i.expires && i.expires < now() });
    }
    return rows.map(({ pw, ...r }) => ({ ...r, reused: rows.filter(x => x.pw === pw).length - 1 }));
  },
  breachPrefixes: async () => [],
  breachMatch: async () => ({}),
  async secrets(vault, id) { return { ...(get(vault).secrets.get(id) ?? {}) }; },
  async totp(vault, id, field) {
    const s = get(vault).secrets.get(id)?.[field] ?? '';
    const t = Date.now();
    return { code: await totp(s, t), remaining: 30 - (Math.floor(t / 1000) % 30), period: 30 };
  },
  async copy(vault, id, field, asTotp, clearAfter) {
    const v = get(vault);
    const raw = item(v, id).fields.find(f => f.name === field);
    const value = asTotp ? (await demo.totp(vault, id, field)).code
      : raw?.protected ? v.secrets.get(id)?.[field] ?? '' : raw?.value ?? '';
    await demo.copyText(value, clearAfter);
  },
  async copyText(text, clearAfter) {
    await navigator.clipboard.writeText(text);
    clearTimeout(clipTimer);
    if (clearAfter) clipTimer = setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), clearAfter * 1000);
  },
  readText: () => navigator.clipboard.readText(),
  desktopApply: async () => [],
  windowMinimize: async () => {},
  windowAfterUnlock: async () => {},
  autotypePerform: async () => {},
  autotypeEntry: async () => {},
  on: () => () => {},
  browserAnswer: async () => {},
  browserSetActive: async () => {},
  log: (level, message) => console[level](message),
  async trash(vault, id) { const v = get(vault); item(v, id).trashed = true; return out(v); },
  async restore(vault, id) { const v = get(vault); item(v, id).trashed = false; return out(v); },
  async remove(vault, id) { const v = get(vault); v.data.items = v.data.items.filter(i => i.id !== id); return out(v); },
  async emptyTrash(vault) { const v = get(vault); v.data.items = v.data.items.filter(i => !i.trashed); return out(v); },
  async historyRestore(vault, id, index) {
    const v = get(vault);
    const old = v.snapshots.get(id)?.[index];
    if (!old) throw new Error('not_found');
    const cur = item(v, id);
    v.snapshots.set(id, [clone(cur), ...(v.snapshots.get(id) ?? [])].slice(0, 10));
    Object.assign(cur, { ...clone(old), modified: now(), history: (v.snapshots.get(id) ?? []).map(s => s.modified ?? '') });
    return out(v);
  },
  async move(vault, id, folder) {
    const v = get(vault);
    item(v, id).folder = folder ?? v.data.root;
    return out(v);
  },
  async moveToVault(src, id, dst, folder) {
    const s = get(src), d = get(dst);
    const moved = { ...clone(item(s, id)), folder: folder ?? d.data.root, history: [] };
    d.data.items.push(moved);
    d.secrets.set(id, s.secrets.get(id) ?? {});
    s.data.items = s.data.items.filter(i => i.id !== id);
    return [out(s), out(d)];
  },
  async duplicate(vault, id, suffix) {
    const v = get(vault);
    const copy = clone(item(v, id));
    copy.id = crypto.randomUUID();
    copy.history = [];
    copy.modified = now();
    copy.fields = copy.fields.map(f => f.name === 'Title' ? { ...f, value: (f.value ?? '') + suffix } : f);
    v.data.items.push(copy);
    v.secrets.set(copy.id, { ...(v.secrets.get(id) ?? {}) });
    return [copy.id, out(v)];
  },
  async attachmentSave() { /* demo: the UI downloads from memory instead */ },
  async folderCreate(vault, parent, name) {
    const v = get(vault);
    v.data.folders.push({ id: crypto.randomUUID(), name, parent: parent ?? null });
    return out(v);
  },
  async folderRename(vault, id, name) {
    const v = get(vault);
    const f = v.data.folders.find(x => x.id === id);
    if (f) f.name = name;
    return out(v);
  },
  async folderTrash(vault, id) {
    const v = get(vault);
    v.data.folders = v.data.folders.filter(f => f.id !== id);
    v.data.items.forEach(i => { if (i.folder === id) { i.trashed = true; i.folder = v.data.root; } });
    return out(v);
  },
};

/** Demo only: bytes of an attachment added in this session (desktop saves via dialog). */
export const demoAttachment = (vault: string, id: string, name: string) => demoVaults.get(vault)?.files.get(id + '/' + name);

export const backend: Backend = '__TAURI_INTERNALS__' in window ? desktop : demo;

/** Maps backend error codes to something a user can act on. */
export const errorCode = (e: unknown) => String(e instanceof Error ? e.message : e).split(':')[0];
