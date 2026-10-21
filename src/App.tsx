import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { save as saveDialog } from '@tauri-apps/plugin-dialog';
import { backend, demoAttachment, type AutoTypePick, type BrowserAsk, type Health, type Totp, type Update, type VaultData } from './backend';
import { draftToInput, iconUrl, rawToItem, type Attachment, type Draft, type Field, type FieldKind, type Folder, type Item, type ItemType, type VaultInfo } from './model';
import { DEMO_VAULTS } from './mock';
import { openExternal, openOptions } from './open';
import { clearHistory, generate } from './generator';
import { colorize } from './colorize';
import { LANGS, strings, type Lang, type Strings } from './i18n';
import { DEFAULTS, mergePrefs, type Prefs } from './settings';
import { settingsStrings } from './i18n-settings';
// rarely needed views load on first use (keeps startup lean)
const SettingsPage = lazy(() => import('./SettingsPage'));
const Generator = lazy(() => import('./GeneratorDialog'));
const ImportDialog = lazy(() => import('./ImportDialog'));
import VaultDialog, { fileName, type Known } from './VaultDialog';
import { Icon } from './Icon';
import { SshPanel } from './SshPanel';
import { PasswordStrength } from './PasswordStrength';
import { VaultSettingsDialog } from './VaultSettingsDialog';
import { ShareDialog } from './ShareDialog';
import { HealthOverview, HealthRow, ISSUE_ICON, ISSUES, issueName as issueNameOf, type Issue } from './HealthOverview';
import { TotpSetup } from './TotpSetup';
import { ContextMenuProvider, useContextMenu, type MenuItem } from './ContextMenu';

type Theme = 'dark' | 'light';
type Settings = Prefs;

const TYPE_ICON: Record<ItemType, string> = {
  login: 'person', card: 'credit_card', note: 'sticky_note_2', pin: 'pin', identity: 'badge', other: 'category',
};
const FIELD_ICON: Partial<Record<keyof Strings, string>> = {
  username: 'person', password: 'key', website: 'language', cardholder: 'badge', number: 'credit_card',
  expires: 'event', cvc: 'password', pin: 'pin', totp: 'timer', noteBody: 'notes',
  fullName: 'person', email: 'mail', phone: 'call', address: 'home', birthdate: 'cake',
};
const MULTILINE = new Set<keyof Strings>(['noteBody', 'address']);

// Field templates per new-item type. KeePass has no item types; type is stored in entry custom data.
const TEMPLATES: Partial<Record<ItemType, Field[]>> = {
  login: [{ key: 'username', value: '' }, { key: 'password', value: '', kind: 'hidden' }, { key: 'website', value: '', kind: 'url' }],
  card: [
    { key: 'cardholder', value: '' }, { key: 'number', value: '', kind: 'hidden' }, { key: 'expires', value: '' },
    { key: 'cvc', value: '', kind: 'hidden' }, { key: 'pin', value: '', kind: 'hidden' },
  ],
  identity: [
    { key: 'fullName', value: '' }, { key: 'email', value: '' }, { key: 'phone', value: '' },
    { key: 'address', value: '' }, { key: 'birthdate', value: '', kind: 'date' },
  ],
};
const NEW_TYPES: ItemType[] = ['login', 'card', 'note', 'identity', 'other'];

const ALL = 'all';
const TRASH = 'trash';
const HEALTH = 'health';
const SETTINGS_KEY = 'anotherkeepass.settings';
// options Rust needs before/without the UI (tray, autostart, window behaviour, auto-type)
const DESKTOP_KEYS = [
  'singleInstance', 'autostart', 'startMinimized', 'trayIcon', 'hideToTray',
  'lockOnMinimize', 'lockOnSession', 'lockOnUserSwitch', 'screenProtect',
  'atShortcut', 'atStartDelay', 'atCharDelay', 'atAlwaysAsk', 'atMatchTitle', 'atMatchUrl', 'atHideExpired',
  'browserEnabled', 'bChrome', 'bFirefox', 'bChromium', 'bEdge', 'bBrave', 'bVivaldi', 'bTor', 'bUnlock', 'bMatchScheme',
  'bBestMatch', 'bAllowExpired', 'bSearchAll', 'bNoAccessConfirm', 'bUpdateNoConfirm', 'bKph', 'bUpdateManifests',
  'bCustomProxy', 'bProxyPath', 'bSkipBasicAuth', 'bLocalhostPasskeys', 'backupBeforeSave', 'backupPath', 'autoReload', 'atRelock', 'atRemember', 'trayStyle', 'sshEnabled', 'sshAuthSock', 'ksImport', 'ksExport',
] as const;
const KNOWN_KEY = 'anotherkeepass.vaults';
const today = () => new Date().toISOString().slice(0, 10);

// ponytail: localStorage (WebView storage); a Tauri store plugin is only needed if settings must be shared across profiles
// null = first run → setup wizard
function loadSettings(): Settings | null {
  try {
    const raw = JSON.parse(localStorage.getItem(SETTINGS_KEY) ?? 'null');
    return raw ? mergePrefs(raw) : null;
  } catch { return null; }
}
function saveSettings(s: Settings) {
  try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(s)); } catch { /* private mode: settings live for this session only */ }
}
/** Remembered vault files (paths + look only, never keys). The browser demo starts with its demo files. */
function loadKnown(): Known[] {
  try {
    const raw = JSON.parse(localStorage.getItem(KNOWN_KEY) ?? 'null');
    if (Array.isArray(raw)) return raw;
  } catch { /* fall through */ }
  return backend.desktop ? [] : DEMO_VAULTS;
}
function saveKnown(k: Known[]) {
  try { localStorage.setItem(KNOWN_KEY, JSON.stringify(k)); } catch { /* not persisted */ }
}

export default function App() {
  const [settings, setSettings] = useState<Settings | null>(loadSettings);
  const [open, setOpen] = useState<Record<string, VaultData>>({});
  const [known, setKnown] = useState<Known[]>(loadKnown);
  const [missing, setMissing] = useState<string[]>([]);
  const forget = useCallback((paths: string[]) => setKnown(list => {
    const next = list.filter(k => !paths.includes(k.path));
    saveKnown(next);
    return next;
  }), []);
  // once at start: drop remembered vault files that were deleted or moved
  useEffect(() => {
    const list = loadKnown();
    if (!list.length) return;
    backend.pathsExist(list.map(k => k.path)).then(ok => {
      const gone = list.filter((_, i) => !ok[i]);
      if (!gone.length) return;
      forget(gone.map(g => g.path));
      setMissing(gone.map(g => g.name));
      backend.log('info', 'removed ' + gone.length + ' missing vault file(s) from the list');
    }).catch(() => { /* keep the list if the check fails */ });
  }, [forget]);
  const lang = settings?.lang ?? 'en';
  const theme = settings?.theme ?? 'dark';
  const t = strings[lang];

  const zoom = (settings?.fontSize ?? 100) / 100;
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.lang = lang;
    document.documentElement.style.setProperty('--zoom', String(zoom));
  }, [theme, lang, zoom]);

  openOptions.minimize = !!settings?.minimizeOnUrl;
  const update = (s: Settings) => { setSettings(s); saveSettings(s); };

  const opened = (data: VaultData, meta: Known) => {
    setOpen(o => ({ ...o, [data.id]: data }));
    if (settings?.rememberRecent ?? true) {
      if (!(settings?.rememberKeyfiles ?? true)) meta = { ...meta, keyfile: undefined };
      setKnown(list => {
        const next = [meta, ...list.filter(k => k.path !== meta.path)].slice(0, settings?.recentCount ?? 5);
        saveKnown(next);
        return next;
      });
    }
  };
  const onUpdate = useCallback((d: VaultData) => setOpen(o => ({ ...o, [d.id]: d })), []);
  const [desktopProblems, setDesktopProblems] = useState<string[]>([]);
  useEffect(() => {
    if (!settings || !backend.desktop) return;
    const prefs = {
      ...Object.fromEntries(DESKTOP_KEYS.map(k => [k, settings[k]])), trayLabels: [t.trayShow, t.trayLockAll, t.trayQuit],
      // Windows Hello: instead of the password after a lock, or in addition to it on every unlock
      quickUnlock: settings.helloUnlock && !settings.helloRequirePassword,
      helloBoth: settings.helloUnlock && settings.helloRequirePassword,
    };
    backend.desktopApply(prefs).then(setDesktopProblems).catch(e => { backend.log('error', 'desktopApply: ' + String(e)); setDesktopProblems([String(e)]); });
  }, [settings, t]);
  const onClosed = useCallback((id: string) => setOpen(o => { const n = { ...o }; delete n[id]; return n; }), []);
  const lock = useCallback(async () => {
    await backend.lockAll().catch(() => { /* nothing open */ });
    clearHistory();
    setOpen({});
  }, []);

  // Rust locked everything (tray menu, screen lock, minimize): drop the UI state too
  useEffect(() => backend.on('akp-locked', () => { clearHistory(); setOpen({}); }), []);
  useEffect(() => backend.on<VaultData>('akp-vault-updated', d => setOpen(o => o[d.id] ? { ...o, [d.id]: d } : o)), []);

  if (!settings) return <Setup onDone={s => update({ ...DEFAULTS, ...s })} />;
  return (
    <ContextMenuProvider t={t}>
      {!Object.keys(open).length
        ? <VaultDialog t={t} known={known} missing={missing} onMissing={p => forget([p])}
            onOpened={(d, meta) => { opened(d, meta); if (settings.minimizeAfterUnlock) backend.windowAfterUnlock(); }} />
        : <Vaults t={t} settings={settings} onSettings={update} open={open} known={known}
          onOpened={opened} onUpdate={onUpdate} onClosed={onClosed} onLock={lock} desktopProblems={desktopProblems} />}
    </ContextMenuProvider>
  );
}

type Confirm = { title: string; body: string; label: string; icon: string; action: () => void };

function Vaults({ t, settings, onSettings, open, known, onOpened, onUpdate, onClosed, onLock, desktopProblems }: {
  t: Strings; settings: Settings; onSettings: (s: Settings) => void;
  open: Record<string, VaultData>; known: Known[];
  onOpened: (d: VaultData, meta: Known) => void; onUpdate: (d: VaultData) => void; onClosed: (id: string) => void; onLock: () => void;
  desktopProblems: string[];
}) {
  const [vault, setVault] = useState(ALL);
  const [folder, setFolder] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [tab, setTab] = useState<'all' | 'recent'>('all');
  const [selected, setSelected] = useState<string | null>(null);
  const [pending, setPending] = useState<Item | null>(null); // new entry, not saved yet
  const [newMenu, setNewMenu] = useState(false);
  const [showGen, setShowGen] = useState(false);
  const [importFor, setImportFor] = useState<string | null>(null);
  const [shareFor, setShareFor] = useState<Folder | null>(null);
  const [settingsFor, setSettingsFor] = useState<{ vault: string; upgrade?: boolean } | null>(null);
  // update check: at most once a week, only when enabled
  const [update, setUpdate] = useState<Update | null>(null);
  useEffect(() => {
    if (!settings.updateCheck || !backend.desktop) return;
    const KEY = 'anotherkeepass.updateChecked';
    let last = 0;
    try { last = Number(localStorage.getItem(KEY) ?? 0); } catch { /* no storage */ }
    if (Date.now() - last < 7 * 86_400_000) return;
    backend.updateCheck(settings.updateBeta).then(u => {
      try { localStorage.setItem(KEY, String(Date.now())); } catch { /* no storage */ }
      if (u) { setUpdate(u); notify(t.updateAvailable.replace('{v}', u.version)); }
    }).catch(e => backend.log('warn', 'update check: ' + String(e)));
  }, [settings.updateCheck, settings.updateBeta]); // eslint-disable-line react-hooks/exhaustive-deps // target vault of the import dialog
  const [folderDialog, setFolderDialog] = useState<{ mode: 'create' | 'rename'; vault?: string; id?: string; name?: string; parent?: string } | null>(null);
  const openMenu = useContextMenu();
  const [vaultDialog, setVaultDialog] = useState<{ path?: string } | null>(null);
  const [keyDialog, setKeyDialog] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const [tag, setTag] = useState<string | null>(null);
  // password health view: report from the backend, optional breach counts (HIBP), issue filter
  const [health, setHealth] = useState<Record<string, Health>>({});
  const [breaches, setBreaches] = useState<Record<string, number> | null>(null);
  const [checking, setChecking] = useState(false);
  const [issue, setIssue] = useState<Issue | null>(null);
  useEffect(() => {
    if (vault !== HEALTH) return;
    backend.healthReport().then(r => setHealth(Object.fromEntries(r.map(h => [h.id, h])))).catch(() => {});
  }, [vault, open]);
  useEffect(() => { setBreaches(null); }, [open]);
  const [dragOver, setDragOver] = useState<string | null>(null);
  const dragItem = useRef<Item | null>(null);
  const [showKeys, setShowKeys] = useState(false);
  const [pick, setPick] = useState<AutoTypePick | null>(null);
  const [ask, setAsk] = useState<BrowserAsk | null>(null);
  useEffect(() => backend.on<BrowserAsk>('akp-browser-ask', a => setAsk(a)), []);
  const searchRef = useRef<HTMLInputElement>(null);
  const [snack, setSnack] = useState('');
  const [snackError, setSnackError] = useState(false);
  const notify = (msg: string, error = false) => { setSnack(msg); setSnackError(error); };
  useEffect(() => backend.on('akp-vault-reloaded', () => { setSnack(t.vaultReloaded); setSnackError(false); }), [t.vaultReloaded]);
  const [page, setPage] = useState<'vault' | 'settings'>('vault');
  // drawer collapses to an icon rail: automatically on narrow windows, or via the toggle
  const narrow = '(max-width: 1199px)';
  const [isNarrow, setIsNarrow] = useState(() => window.matchMedia(narrow).matches);
  const [rail, setRail] = useState(isNarrow);
  useEffect(() => {
    const mq = window.matchMedia(narrow);
    const onChange = () => { setIsNarrow(mq.matches); setRail(mq.matches); };
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);
  const clipTimer = useRef<number>(undefined);
  const ts = settingsStrings[settings.lang];

  useEffect(() => {
    if (!snack) return;
    const id = setTimeout(() => setSnack(""), snackError ? 5000 : Math.max(2000, snack.length * 60)); // longer text stays longer
    return () => clearTimeout(id);
  }, [snack, snackError]);

  // auto-lock after inactivity
  useEffect(() => {
    if (!settings.autoLock) return;
    let id = setTimeout(onLock, settings.autoLockSeconds * 1000);
    const reset = () => { clearTimeout(id); id = setTimeout(onLock, settings.autoLockSeconds * 1000); };
    const events = ['pointermove', 'pointerdown', 'keydown', 'wheel'] as const;
    events.forEach(e => window.addEventListener(e, reset));
    return () => { clearTimeout(id); events.forEach(e => window.removeEventListener(e, reset)); };
  }, [settings.autoLock, settings.autoLockSeconds, onLock]);

  // clear search query after it sat untouched
  useEffect(() => {
    if (!settings.clearSearch || !query) return;
    const id = setTimeout(() => setQuery(''), settings.clearSearchMinutes * 60_000);
    return () => clearTimeout(id);
  }, [query, settings.clearSearch, settings.clearSearchMinutes]);
  useEffect(() => () => clearTimeout(clipTimer.current), []);

  const items = useMemo(() => Object.values(open).flatMap(v => v.items.map(r => rawToItemCached(r, v))), [open]);
  const allItems = pending ? [...items, pending] : items;
  const folders: Folder[] = useMemo(() => Object.values(open).flatMap(v =>
    v.folders.map(f => ({ id: f.id, vault: v.id, name: f.name, parent: f.parent, share: f.share }))), [open]);
  const vaultList: VaultInfo[] = useMemo(() => {
    const ids = [...known.map(k => k.path), ...Object.keys(open).filter(id => !known.some(k => k.path === id))];
    return ids.map(id => {
      const k = known.find(x => x.path === id);
      return { id, name: open[id]?.name ?? k?.name ?? fileName(id), file: fileName(id), color: k?.color ?? '--v-clay', icon: k?.icon ?? 'shield_lock', locked: !open[id] };
    });
  }, [known, open]);

  // KDBX 3.1 files: say once that saving upgrades them (a backup is written next to the file)
  const formatNoticed = useRef(new Set<string>());
  useEffect(() => {
    for (const v of Object.values(open)) {
      if (v.format.startsWith('KDBX 3') && !formatNoticed.current.has(v.id)) {
        formatNoticed.current.add(v.id);
        notify(`${v.name}: ${t.kdbx3Notice}`);
      }
    }
  }, [open, t.kdbx3Notice]);

  // auto-type: picker request and errors come from Rust
  useEffect(() => {
    const a = backend.on<AutoTypePick>('akp-autotype-pick', p => setPick(p));
    const b = backend.on<string>('akp-autotype-error', e => notify(`${t.autoTypeError}: ${e}`, true));
    return () => { a(); b(); };
  }, [t.autoTypeError]);
  useEffect(() => {
    if (desktopProblems.length) notify(`${t.desktopProblem}: ${desktopProblems.join(', ')}`, true);
  }, [desktopProblems, t.desktopProblem]);

  // the extension's "database" is the selected vault (or the first open one)
  useEffect(() => { backend.browserSetActive(open[vault] ? vault : Object.keys(open)[0] ?? null); }, [vault, open]);

  // once per unlock: tell about entries that expire soon
  const expiringShown = useRef(false);
  useEffect(() => {
    if (expiringShown.current || !settings.showExpiring) return;
    expiringShown.current = true;
    const limit = new Date(Date.now() + settings.expiryDays * 86_400_000).toISOString().slice(0, 10);
    const n = items.filter(i => !i.trashed && i.expires && i.expires <= limit).length;
    if (n) notify(`${n} ${t.expiringSoon}`);
  }, [items, settings.showExpiring, settings.expiryDays, t.expiringSoon]);

  const run = async <T,>(p: Promise<T>): Promise<T | undefined> => {
    try { return await p; } catch (e) { notify(`${t.saveError}: ${String(e)}`, true); return undefined; }
  };
  const apply = (d: VaultData | undefined) => { if (d) onUpdate(d); return !!d; };

  const clearAfter = settings.clipboardClear ? settings.clipboardSeconds : null;
  const copied = (what: string) => {
    notify(`${what} ${t.copied}`);
    if (settings.onCopy !== 'none') backend.windowMinimize();
    clearTimeout(clipTimer.current);
    if (clearAfter) clipTimer.current = setTimeout(() => notify(ts.ui.clipboardCleared), clearAfter * 1000);
  };
  const copyText = async (text: string, what: string) => {
    if ((await run(backend.copyText(text, clearAfter))) !== undefined || !backend.desktop) copied(what);
  };
  // stored fields are copied by the backend, so secrets never pass through the UI
  const copyField = async (item: Item, f: Field, what: string) => {
    if (item.id.startsWith('new:') || !f.raw) return copyText(f.value, what);
    try { await backend.copy(item.vault, item.id, f.raw, f.kind === 'totp', clearAfter); copied(what); }
    catch (e) { notify(`${t.saveError}: ${String(e)}`, true); }
  };

  const issuesOf = useCallback((id: string): Issue[] => {
    const h = health[id];
    if (!h) return [];
    return ISSUES.filter(k => k === 'breached' ? (breaches?.[id] ?? 0) > 0 : k === 'reused' ? h.reused > 0 : h[k]);
  }, [health, breaches]);
  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (vault === HEALTH) {
      const rank = (i: Item) => issuesOf(i.id).reduce((s, k) => s + (5 - ISSUES.indexOf(k)) ** 2, 0);
      return allItems
        .filter(i => !i.trashed && (issue ? issuesOf(i.id).includes(issue) : issuesOf(i.id).length > 0))
        .filter(i => !q || (i.title + ' ' + i.subtitle).toLowerCase().includes(q))
        .sort((a, b) => rank(b) - rank(a) || a.title.localeCompare(b.title))
        .map(i => ({ ...i, pinned: false }));
    }
    let list = allItems.filter(i => vault === TRASH ? i.trashed
      : !i.trashed && (vault === ALL || i.vault === vault) && (!folder || i.folder === folder));
    if (q) list = list.filter(i => (i.title + ' ' + i.subtitle + ' ' + (i.tags ?? []).join(' ')).toLowerCase().includes(q));
    if (tag) list = list.filter(i => i.tags?.includes(tag));
    return [...list].sort((a, b) =>
      tab === 'recent' ? b.modified.localeCompare(a.modified) : a.title.localeCompare(b.title));
  }, [allItems, vault, folder, query, tab, tag, issue, issuesOf]); // eslint-disable-line react-hooks/exhaustive-deps
  // tags present in the current vault/folder scope, for the filter chips
  const scopeTags = useMemo(() => [...new Set(allItems
    .filter(i => vault === TRASH ? i.trashed : !i.trashed && (vault === ALL || i.vault === vault) && (!folder || i.folder === folder))
    .flatMap(i => i.tags ?? []))].sort((a, b) => a.localeCompare(b)), [allItems, vault, folder]);

  const openIds = Object.keys(open);
  const targetVault = open[vault] ? vault : openIds[0];
  const createItem = (type: ItemType) => {
    const item: Item = {
      id: 'new:' + crypto.randomUUID(), vault: targetVault, type, title: '', subtitle: '',
      folder: folder && folders.some(f => f.id === folder && f.vault === targetVault) ? folder : undefined,
      fields: (TEMPLATES[type] ?? []).map(f => f.key === 'password' && settings.generateForNew
        ? { ...f, value: generate({ length: 20, upper: true, digits: true, symbols: true }) }
        : { ...f }),
      modified: today(), tags: [], attachments: [], history: [],
    };
    setPending(item);
    setSelected(item.id);
    setNewMenu(false);
  };
  const saveItem = async (item: Item, draft: Draft) => {
    const input = await draftToInput(item, draft, open[item.vault].root);
    const res = await run(backend.save(item.vault, input));
    if (!res) return false;
    onUpdate(res[1]);
    setPending(null);
    setSelected(res[0]);
    return true;
  };
  const discardNew = () => { setPending(null); setSelected(null); };

  const doTrash = async (item: Item) => {
    if (apply(await run(backend.trash(item.vault, item.id)))) { setSelected(null); notify(ts.ui.movedToTrash); }
  };
  const requestTrash = (item: Item) => settings.confirmTrash
    ? setConfirm({ title: ts.ui.trashTitle, body: ts.ui.trashBody, label: ts.ui.moveToTrash, icon: 'delete', action: () => doTrash(item) })
    : doTrash(item);
  const restoreItem = async (item: Item) => { if (apply(await run(backend.restore(item.vault, item.id)))) notify(t.restore); };
  const deleteForever = (item: Item) => setConfirm({
    title: t.deleteForever, body: t.deleteForeverBody, label: t.deleteForever, icon: 'delete_forever',
    action: async () => { if (apply(await run(backend.remove(item.vault, item.id)))) setSelected(null); },
  });
  const emptyTrash = () => setConfirm({
    title: t.emptyTrash, body: t.emptyTrashBody, label: t.emptyTrash, icon: 'delete_forever',
    action: async () => {
      for (const id of new Set(items.filter(i => i.trashed).map(i => i.vault))) apply(await run(backend.emptyTrash(id)));
      setSelected(null);
    },
  });
  const togglePin = async (item: Item) => {
    const draft: Draft = { title: item.title, folder: item.folder ?? '', note: item.note ?? '', fields: item.fields, attachments: item.attachments ?? [], expires: item.expires ?? null, tags: item.tags ?? [] };
    const input = await draftToInput({ ...item, pinned: !item.pinned }, draft, open[item.vault].root);
    const res = await run(backend.save(item.vault, input));
    if (res) onUpdate(res[1]);
  };
  const moveItem = async (it: Item, vaultId: string, folderId: string | null) => {
    if (it.id.startsWith('new:')) return;
    const target = folderId ? folders.find(f => f.id === folderId)?.name : vaultList.find(v => v.id === vaultId)?.name;
    if (it.vault === vaultId) {
      if ((it.folder ?? null) === folderId && !it.trashed) return;
      if (!apply(await run(backend.move(vaultId, it.id, folderId)))) return;
    } else {
      const res = await run(backend.moveToVault(it.vault, it.id, vaultId, folderId));
      if (!res) return;
      onUpdate(res[0]);
      onUpdate(res[1]);
    }
    notify(`${t.movedTo} ${target}`);
  };
  // drop target props for vault and folder rows
  const dropProps = (key: string, vaultId: string, folderId: string | null) => ({
    onDragOver: (e: React.DragEvent) => { if (dragItem.current && open[vaultId]) { e.preventDefault(); e.dataTransfer.dropEffect = 'move'; setDragOver(key); } },
    onDragLeave: () => setDragOver(k => k === key ? null : k),
    onDrop: (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(null);
      const it = dragItem.current;
      dragItem.current = null;
      if (it) moveItem(it, vaultId, folderId);
    },
  });
  const duplicate = async (item: Item) => {
    const res = await run(backend.duplicate(item.vault, item.id, ` (${t.copySuffix})`));
    if (res) { onUpdate(res[1]); setSelected(res[0]); }
  };

  // keyboard shortcuts (KeePassXC-like); entry-level ones act on the selected entry
  const shortcutRef = useRef<(e: KeyboardEvent) => void>(() => {});
  shortcutRef.current = (e: KeyboardEvent) => {
    const typing = e.target instanceof Element && e.target.closest('input, textarea, select, [contenteditable=true]') !== null;
    const mod = e.ctrlKey || e.metaKey;
    const field = (raw: string) => current?.fields.find(f => f.raw === raw);
    const totpField = current?.fields.find(f => f.kind === 'totp');
    const run1 = (fn: () => void) => { e.preventDefault(); fn(); };
    if (e.key === 'F5' || (mod && ['r', 'p', 'j', 'h', 'g', 's', 'o'].includes(e.key.toLowerCase()))) { e.preventDefault(); return; }
    if (e.key === 'F1' || (mod && e.key === '/')) return run1(() => setShowKeys(s => !s));
    if (e.key === 'Escape') { window.dispatchEvent(new Event('akp:cancel')); setShowKeys(false); return; }
    if (mod && e.key.toLowerCase() === 'f') return run1(() => searchRef.current?.focus());
    if (mod && e.key.toLowerCase() === 'l') return run1(onLock);
    if (mod && e.key.toLowerCase() === 'n' && targetVault) return run1(() => createItem('login'));
    if (!current || current.id.startsWith('new:')) return;
    if (mod && e.key.toLowerCase() === 'e') return run1(() => window.dispatchEvent(new Event('akp:edit')));
    if (typing) return; // below: keys that would clash with text editing
    if (mod && e.key.toLowerCase() === 'b' && field('UserName')) return run1(() => copyField(current, field('UserName')!, t.username));
    if (mod && e.key.toLowerCase() === 'c' && !window.getSelection()?.toString() && field('Password')) return run1(() => copyField(current, field('Password')!, t.password));
    if (mod && e.key.toLowerCase() === 't' && totpField) return run1(() => copyField(current, totpField, t.totp));
    if (mod && e.key.toLowerCase() === 'u' && field('URL')?.value) return run1(() => openExternal(field('URL')!.value));
    if (mod && e.key.toLowerCase() === 'd') return run1(() => duplicate(current));
    if (mod && e.shiftKey && e.key.toLowerCase() === 'v' && backend.desktop) return run1(() => run(backend.autotypeEntry(current.vault, current.id)));
    if (e.key === 'Delete' && !current.trashed) return run1(() => requestTrash(current));
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      const list = [...pinned, ...rest];
      const i = list.findIndex(x => x.id === current.id) + (e.key === 'ArrowDown' ? 1 : -1);
      if (list[i]) run1(() => setSelected(list[i].id));
    }
  };
  useEffect(() => {
    const h = (e: KeyboardEvent) => shortcutRef.current(e);
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, []);

  const itemMenu = (it: Item): MenuItem[] => {
    const f = (raw: string) => it.fields.find(x => x.raw === raw && (x.value || x.protected));
    const totpF = it.fields.find(x => x.kind === 'totp');
    const edit = () => { setSelected(it.id); setTimeout(() => window.dispatchEvent(new Event('akp:edit')), 50); };
    if (it.trashed) return [
      { icon: 'restore_from_trash', label: t.restore, action: () => restoreItem(it) },
      { icon: 'delete_forever', label: t.deleteForever, danger: true, action: () => deleteForever(it) },
    ];
    return [
      ...(f('UserName') ? [{ icon: 'person', label: t.scCopyUser, kbd: 'Ctrl+B', action: () => copyField(it, f('UserName')!, t.username) }] : []),
      ...(f('Password') ? [{ icon: 'key', label: t.scCopyPw, kbd: 'Ctrl+C', action: () => copyField(it, f('Password')!, t.password) }] : []),
      ...(totpF ? [{ icon: 'timer', label: t.scCopyTotp, kbd: 'Ctrl+T', action: () => copyField(it, totpF, t.totp) }] : []),
      ...(f('URL')?.value ? [{ icon: 'open_in_new', label: t.scOpenUrl, kbd: 'Ctrl+U', action: () => openExternal(f('URL')!.value) }] : []),
      ...(backend.desktop ? [{ icon: 'keyboard', label: t.autoType, kbd: 'Ctrl+Shift+V', action: () => run(backend.autotypeEntry(it.vault, it.id)) }] : []),
      'sep',
      { icon: 'edit', label: t.edit, kbd: 'Ctrl+E', action: edit },
      { icon: 'content_copy', label: t.duplicate, kbd: 'Ctrl+D', action: () => duplicate(it) },
      { icon: 'push_pin', label: it.pinned ? t.unpinItem : t.pinItem, action: () => togglePin(it) },
      ...(f('URL')?.value && backend.desktop ? [{ icon: 'image_search', label: t.loadIcon, action: () => loadIcons([it]) }] : []),
      ...(it.icon ? [{ icon: 'hide_image', label: t.removeIcon, action: () => removeIcon(it) }] : []),
      'sep',
      { icon: 'delete', label: ts.ui.moveToTrash, kbd: 'Entf', danger: true, action: () => requestTrash(it) },
    ];
  };
  // website icons: download (backend), scale to a 64 px PNG here, store as KeePass custom icons
  const loadIcons = async (list: Item[]) => {
    const withUrl = list.filter(i => i.fields.some(f => f.raw === 'URL' && f.value));
    if (!withUrl.length) return;
    if (withUrl.length > 1) notify(t.iconsLoading);
    const found: Record<string, [string, string | null][]> = {};
    for (let i = 0; i < withUrl.length; i += 4) {
      await Promise.all(withUrl.slice(i, i + 4).map(async it => {
        try {
          const raw = await backend.faviconFetch(it.fields.find(f => f.raw === 'URL')!.value, settings.ddgFavicons, settings.faviconTimeout);
          const png = await toPng(raw);
          if (png) (found[it.vault] ??= []).push([it.id, png]);
        } catch { /* no icon for this site */ }
      }));
    }
    let n = 0;
    for (const [vid, icons] of Object.entries(found)) if (apply(await run(backend.iconsSet(vid, icons)))) n += icons.length;
    notify(n ? `${n} ${t.iconsLoaded}` : t.iconNone, !n);
  };
  const removeIcon = async (it: Item) => { apply(await run(backend.iconsSet(it.vault, [[it.id, null]]))); };
  const folderMenu = (f: Folder): MenuItem[] => [
    { icon: 'create_new_folder', label: t.newSubfolder, action: () => setFolderDialog({ mode: 'create', vault: f.vault, parent: f.id }) },
    { icon: 'drive_file_rename_outline', label: t.renameFolder, action: () => setFolderDialog({ mode: 'rename', vault: f.vault, id: f.id, name: f.name }) },
    ...(backend.desktop ? [{ icon: 'folder_shared', label: t.shareFolder, action: () => setShareFor(f) }] : []),
    'sep',
    { icon: 'delete', label: t.deleteFolder, danger: true, action: () => setConfirm({ title: t.deleteFolder, body: ts.ui.trashBody, label: ts.ui.moveToTrash, icon: 'delete',
      action: async () => { if (apply(await run(backend.folderTrash(f.vault, f.id)))) setFolder(null); } }) },
  ];
  const vaultMenu = (v: VaultInfo): MenuItem[] => v.locked
    ? [{ icon: 'lock_open', label: t.unlockVault, action: () => setVaultDialog({ path: v.id }) }]
    : [
      { icon: 'create_new_folder', label: t.newFolder, action: () => setFolderDialog({ mode: 'create', vault: v.id, parent: '' }) },
      { icon: 'upload_file', label: t.importItems, action: () => setImportFor(v.id) },
      ...(backend.desktop ? [{ icon: 'image_search', label: t.loadIcons, action: () => loadIcons(items.filter(i => i.vault === v.id && !i.trashed && !i.icon)) }] : []),
      { icon: 'tune', label: t.vaultSettings, action: () => setSettingsFor({ vault: v.id }) },
      { icon: 'key', label: t.changeMasterKey, action: () => setKeyDialog(v.id) },
      'sep',
      { icon: 'lock', label: t.closeVault, action: () => closeVault(v.id) },
    ];

  const historyRestore = async (item: Item, index: number) => apply(await run(backend.historyRestore(item.vault, item.id, index)));
  const download = async (item: Item, a: Attachment) => {
    if (backend.desktop && !a.file) {
      const dest = await saveDialog({ defaultPath: a.name });
      if (dest) await run(backend.attachmentSave(item.vault, item.id, a.name, dest));
      return;
    }
    const bytes = a.file ? new Uint8Array(await a.file.arrayBuffer()) : demoAttachment(item.vault, item.id, a.name);
    if (!bytes) return;
    const url = URL.createObjectURL(new Blob([bytes.slice()])); // slice: plain ArrayBuffer copy
    Object.assign(document.createElement('a'), { href: url, download: a.name }).click();
    URL.revokeObjectURL(url);
  };

  const closeVault = async (id: string) => {
    await run(backend.close(id));
    if (vault === id) { setVault(ALL); setFolder(null); }
    setSelected(null);
    onClosed(id);
  };
  const selectVault = (id: string) => {
    const v = vaultList.find(x => x.id === id);
    if (v?.locked) { setVaultDialog({ path: id }); return; }
    setVault(id); setFolder(null);
    if (isNarrow) setRail(true);
  };

  // declarations (hoisted): visible above already uses them
  function issueName(k: Issue) { return issueNameOf(t, k); }
  function issueLabel(k: Issue, id: string) {
    if (k === 'breached') return `${(breaches?.[id] ?? 0).toLocaleString()} ${t.hBreachedN}`;
    if (k === 'reused') return `${t.hReused} (${(health[id]?.reused ?? 0) + 1}×)`;
    return issueName(k);
  }
  // HIBP range API with k-anonymity: only 5 hex chars of each SHA-1 leave the machine
  const checkBreaches = async () => {
    setChecking(true);
    try {
      const prefixes = await backend.breachPrefixes();
      const ranges: Record<string, string> = {};
      for (let i = 0; i < prefixes.length; i += 6) {
        await Promise.all(prefixes.slice(i, i + 6).map(async p => {
          const r = await fetch(`https://api.pwnedpasswords.com/range/${p}`, { headers: { 'Add-Padding': 'true' } });
          if (!r.ok) throw new Error(`HTTP ${r.status}`);
          ranges[p] = await r.text();
        }));
      }
      const found = await backend.breachMatch(ranges);
      setBreaches(found);
      if (!Object.keys(found).length) notify(t.hNoBreaches);
      else setIssue('breached');
    } catch (e) { notify(`${t.hCheck}: ${String(e)}`, true); }
    setChecking(false);
  };

  const healthCounts = {
    ok: Object.keys(health).filter(id => !issuesOf(id).length).length,
    ...Object.fromEntries(ISSUES.map(k => [k, Object.keys(health).filter(id => issuesOf(id).includes(k)).length])),
  } as Record<Issue | 'ok', number>;
  const current = allItems.find(i => i.id === selected) ?? null;
  const pinned = visible.filter(i => i.pinned);
  const rest = visible.filter(i => !i.pinned);
  const snackbar = snack && <div className={'snackbar' + (snackError ? ' error' : '')} role="status"><Icon n={snackError ? 'error' : 'check_circle'} />{snack}</div>;
  const activeVault = vaultList.find(v => v.id === vault && !v.locked);
  const depth = (f: Folder): number => f.parent ? 1 + depth(folders.find(x => x.id === f.parent) ?? { ...f, parent: null }) : 0;

  if (page === 'settings') {
    return (
      <>
        <Suspense fallback={null}>
          <SettingsPage t={t} prefs={settings} onChange={onSettings} onBack={() => setPage('vault')} onSnack={notify} />
        </Suspense>
        {snackbar}
      </>
    );
  }

  return (
    // narrow window: grid keeps the rail column, an opened drawer floats over the content
    <div className={'app' + (rail ? ' rail' : '') + (isNarrow ? ' narrow' : '')}>
      {isNarrow && !rail && <div className="drawer-scrim" onClick={() => setRail(true)} />}
      <aside className="drawer">
        <div className="brand">
          <button className="logo" onClick={() => setRail(r => !r)} title={t.toggleMenu} aria-label={t.toggleMenu} aria-expanded={!rail}>
            <Icon n={rail ? 'menu' : 'encrypted'} fill />
          </button>
          <h1>Another<span>Keepass</span><small>{t.kdbxCompat}</small></h1>
        </div>
        <div className="new-wrap">
          <button className="fab" onClick={() => setNewMenu(m => !m)} aria-expanded={newMenu}><Icon n="add" /><span className="fab-label">{t.newItem}</span></button>
          {newMenu && (
            <>
              <div className="menu-scrim" onClick={() => setNewMenu(false)} />
              <div className="menu new-menu" role="menu">
                {NEW_TYPES.map(type => (
                  <button key={type} role="menuitem" onClick={() => createItem(type)}>
                    <span className={'avatar sm ' + type}><Icon n={TYPE_ICON[type]} /></span>{t[type]}
                  </button>
                ))}
                <hr />
                <button role="menuitem" onClick={() => { setShowGen(true); setNewMenu(false); }}>
                  <span className="avatar sm pin"><Icon n="password" /></span>{t.password}
                </button>
                <button role="menuitem" onClick={() => { setFolderDialog({ mode: 'create', vault: targetVault }); setNewMenu(false); }}>
                  <span className="avatar sm other"><Icon n="create_new_folder" /></span>{t.folder}
                </button>
                <button role="menuitem" onClick={() => { setImportFor(targetVault); setNewMenu(false); }}>
                  <span className="avatar sm note"><Icon n="upload_file" /></span>{t.importItems}
                </button>
              </div>
            </>
          )}
        </div>
        <nav className="nav">
          <span className="label">{t.vaults}</span>
          <NavItem active={vault === ALL} onClick={() => selectVault(ALL)} icon="stacks" bg="--surface-highest"
            name={t.allVaults} count={items.filter(i => !i.trashed).length} />
          {vaultList.map(v => (
            <div key={v.id}>
              <NavItem active={vault === v.id && !folder} onClick={() => selectVault(v.id)} icon={v.locked ? 'lock' : v.icon} bg={v.color}
                name={v.name} sub={v.locked ? `${t.locked} · ${v.file}` : v.file} locked={v.locked}
                drop={v.locked ? undefined : dropProps('v:' + v.id, v.id, null)} over={dragOver === 'v:' + v.id}
                onContextMenu={e => openMenu(e, vaultMenu(v))}
                count={v.locked ? undefined : items.filter(i => i.vault === v.id && !i.trashed).length} />
              {vault === v.id && folders.filter(f => f.vault === v.id).map(f => (
                <div key={f.id} className={'folder-row' + (folder === f.id ? ' active' : '')} style={{ '--depth': depth(f) } as React.CSSProperties}>
                  <button className={'nav-item folder' + (folder === f.id ? ' active' : '') + (dragOver === 'f:' + f.id ? ' drop-over' : '')}
                    onClick={() => setFolder(f.id)} title={f.name} {...dropProps('f:' + f.id, f.vault, f.id)}
                    onContextMenu={e => openMenu(e, folderMenu(f))}>
                    <Icon n={f.share ? 'folder_shared' : folder === f.id ? 'folder_open' : 'folder'} fill={folder === f.id} />
                    <span>{f.name}</span>
                    <span className="count">{items.filter(i => i.folder === f.id && !i.trashed).length}</span>
                  </button>
                  {folder === f.id && (
                    <span className="folder-tools">
                      <button className="icon-btn" title={t.renameFolder} aria-label={t.renameFolder}
                        onClick={() => setFolderDialog({ mode: 'rename', vault: f.vault, id: f.id, name: f.name })}><Icon n="edit" /></button>
                      <button className="icon-btn" title={t.deleteFolder} aria-label={t.deleteFolder}
                        onClick={() => setConfirm({ title: t.deleteFolder, body: ts.ui.trashBody, label: ts.ui.moveToTrash, icon: 'delete',
                          action: async () => { if (apply(await run(backend.folderTrash(f.vault, f.id)))) setFolder(null); } })}><Icon n="delete" /></button>
                    </span>
                  )}
                </div>
              ))}
            </div>
          ))}
          <button className="nav-item add-vault" title={t.addVault} onClick={() => setVaultDialog({})}>
            <span className="vi"><Icon n="add" /></span>
            <span>{t.addVault}</span>
          </button>
          <hr />
          <NavItem active={vault === HEALTH} onClick={() => selectVault(HEALTH)} icon="health_and_safety" bg="--surface-highest" name={t.health} />
          <NavItem active={vault === TRASH} onClick={() => selectVault(TRASH)} icon="delete" bg="--surface-highest"
            name={t.trash} count={items.filter(i => i.trashed).length} />
        </nav>
        <div className="drawer-foot">
          <button className="icon-btn" title={ts.ui.settings} aria-label={ts.ui.settings} onClick={() => setPage('settings')}>
            <Icon n="settings" />
          </button>
          <button className="icon-btn" title={t.theme} aria-label={t.theme}
            onClick={() => onSettings({ ...settings, theme: settings.theme === 'dark' ? 'light' : 'dark' })}>
            <Icon n={settings.theme === 'dark' ? 'light_mode' : 'dark_mode'} />
          </button>
          {update && (
            <button className="icon-btn update-btn" title={t.updateAvailable.replace('{v}', update.version)} aria-label={t.updateAvailable.replace('{v}', update.version)}
              onClick={() => openExternal(update.url)}><Icon n="system_update" /></button>
          )}
          <button className="icon-btn" title={t.lock} aria-label={t.lock} onClick={onLock} style={{ marginLeft: 'auto' }}><Icon n="lock" /></button>
        </div>
      </aside>

      <section className="pane">
        <label className="searchbar">
          <Icon n="search" />
          <input ref={searchRef} placeholder={t.search} value={query} onChange={e => setQuery(e.target.value)} aria-label={t.search} title={`${t.scSearch} (Ctrl+F)`} />
          {query && <button className="icon-btn" onClick={() => setQuery('')} aria-label={t.close}><Icon n="close" /></button>}
        </label>
        {activeVault && (
          <div className="list-head">
            <span title={activeVault.id}>{activeVault.name}</span>
            <button className="icon-btn" title={t.vaultSettings} aria-label={t.vaultSettings} onClick={() => setSettingsFor({ vault: activeVault.id })}><Icon n="tune" /></button>
            <button className="icon-btn" title={t.changeMasterKey} aria-label={t.changeMasterKey} onClick={() => setKeyDialog(activeVault.id)}><Icon n="key" /></button>
            <button className="icon-btn" title={t.closeVault} aria-label={t.closeVault} onClick={() => closeVault(activeVault.id)}><Icon n="lock" /></button>
          </div>
        )}
        {vault === TRASH && items.some(i => i.trashed) && (
          <div className="list-head">
            <span>{t.trash}</span>
            <button className="btn text" onClick={emptyTrash}><Icon n="delete_forever" />{t.emptyTrash}</button>
          </div>
        )}
        {vault === HEALTH ? (
          <div className="tag-filter" role="toolbar" aria-label={t.health}>
            <button className={'chip' + (!issue ? ' on' : '')} onClick={() => setIssue(null)}>{!issue && <Icon n="check" />}{t.hAll}</button>
            {!breaches && (
              <button className="chip" disabled={checking || !backend.desktop} title={t.hCheckHint} onClick={checkBreaches}>
                <Icon n="travel_explore" />{checking ? t.hChecking : t.hCheck}
              </button>
            )}
            {ISSUES.filter(k => k !== 'breached' || breaches).map(k => {
              const n = Object.keys(health).filter(id => issuesOf(id).includes(k)).length;
              return n > 0 && (
                <button key={k} className={'chip issue-chip ' + k + (issue === k ? ' on' : '')} onClick={() => setIssue(x => x === k ? null : k)}>
                  <Icon n={issue === k ? 'check' : ISSUE_ICON[k]} />{issueName(k)} · {n}
                </button>
              );
            })}
          </div>
        ) : <>
        <div className="seg">
          <button className={'chip' + (tab === 'all' ? ' on' : '')} onClick={() => setTab('all')}>
            {tab === 'all' && <Icon n="check" />}{t.all} · {visible.length}
          </button>
          <button className={'chip' + (tab === 'recent' ? ' on' : '')} onClick={() => setTab('recent')}>
            {tab === 'recent' && <Icon n="check" />}{t.recent}
          </button>
        </div>
        {scopeTags.length > 0 && (
          <div className="tag-filter" role="toolbar" aria-label={t.tags}>
            {scopeTags.map(tg => (
              <button key={tg} className={'chip' + (tag === tg ? ' on' : '')} onClick={() => setTag(x => x === tg ? null : tg)}>
                <Icon n="sell" />{tg}
              </button>
            ))}
          </div>
        )}
        </>}
        <div className="items">
          {visible.length === 0 && <div className="empty"><Icon n={vault === HEALTH ? 'verified_user' : 'eco'} />{vault === HEALTH ? t.hOk : t.noItems}</div>}
          {pinned.length > 0 && <span className="label group-label">{t.pinned}</span>}
          {pinned.map(i => <Row key={i.id} t={t} item={i} active={i.id === selected} onClick={() => setSelected(i.id)} dragRef={dragItem} onDragEnd={() => setDragOver(null)}
            onContextMenu={e => { if (!i.id.startsWith('new:')) { setSelected(i.id); openMenu(e, itemMenu(i)); } }} />)}
          {rest.length > 0 && pinned.length > 0 && <span className="label group-label">{t.others}</span>}
          {vault === HEALTH && rest.map(i => <HealthRow key={i.id} t={t} item={i} issues={issuesOf(i.id)} label={k => issueLabel(k, i.id)}
            active={i.id === selected} onClick={() => setSelected(i.id)} />)}
          {vault !== HEALTH && rest.map(i => <Row key={i.id} t={t} item={i} active={i.id === selected} onClick={() => setSelected(i.id)} dragRef={dragItem} onDragEnd={() => setDragOver(null)}
            onContextMenu={e => { if (!i.id.startsWith('new:')) { setSelected(i.id); openMenu(e, itemMenu(i)); } }} />)}
        </div>
      </section>

      <main className="pane detail">
        {current ? (
          <Detail key={current.id} t={t} item={current} prefs={settings}
            vault={vaultList.find(v => v.id === current.vault)!}
            folders={folders.filter(f => f.vault === current.vault)}
            isNew={current.id === pending?.id}
            onCopyField={(f, what) => copyField(current, f, what)}
            onCopyText={copyText}
            loadSecrets={() => backend.secrets(current.vault, current.id)}
            getTotp={field => backend.totp(current.vault, current.id, field)}
            onDuplicate={() => duplicate(current)}
            onSave={d => saveItem(current, d)}
            onDiscard={discardNew}
            onTrash={() => requestTrash(current)}
            onRestore={() => restoreItem(current)}
            onDeleteForever={() => deleteForever(current)}
            onTogglePin={() => togglePin(current)}
            onHistoryRestore={i => historyRestore(current, i)}
            onDownload={a => download(current, a)}
            onLoadIcon={backend.desktop && current.fields.some(f => f.raw === 'URL' && f.value) ? () => loadIcons([current]) : undefined}
            onRemoveIcon={current.icon ? () => removeIcon(current) : undefined}
            onSshChanged={settings.sshEnabled && backend.desktop ? d => onUpdate(d) : undefined} onMessage={notify} />
        ) : (
          vault === HEALTH ? (
            <HealthOverview t={t} total={Object.keys(health).length} counts={healthCounts} breachesChecked={!!breaches} checking={checking}
              canCheck={backend.desktop} onCheck={checkBreaches} active={issue} onPick={setIssue}
              weakVaults={vaultList.filter(v => !v.locked && open[v.id]?.weakKdf).map(v => ({ id: v.id, name: v.name }))}
              onUpgrade={id => setSettingsFor({ vault: id, upgrade: true })} />
          ) : <div className="placeholder"><div><div className="blob"><Icon n="eco" fill /></div>{t.selectItem}</div></div>
        )}
      </main>

      {showGen && <Suspense fallback={null}><Generator t={t} onClose={() => setShowGen(false)} onCopy={copyText} /></Suspense>}
      {showKeys && <ShortcutsDialog t={t} onClose={() => setShowKeys(false)} />}
      {ask && <BrowserAskDialog t={t} ask={ask} vaultName={id => vaultList.find(v => v.id === id)?.name ?? ''}
        onAnswer={answer => { backend.browserAnswer(ask.id, answer); setAsk(null); }} />}
      {pick && (
        <AutoTypePicker t={t} pick={pick} items={items.filter(i => !i.trashed)}
          vaultName={id => vaultList.find(v => v.id === id)?.name ?? ''}
          onClose={() => setPick(null)}
          onPick={(vault, id, sequence) => { setPick(null); run(backend.autotypePerform(vault, id, sequence)); }} />
      )}
      {settingsFor && (
        <VaultSettingsDialog t={t} vault={settingsFor.vault} upgrade={settingsFor.upgrade} onClose={() => setSettingsFor(null)} onSaved={d => onUpdate(d)} />
      )}
      {shareFor && (
        <ShareDialog t={t} vault={shareFor.vault} folder={shareFor.id} name={shareFor.name} onClose={() => setShareFor(null)}
          onSaved={(d, msg) => { onUpdate(d); notify(msg); }} />
      )}
      {importFor !== null && (
        <Suspense fallback={null}>
          <ImportDialog t={t} lang={settings.lang} vaults={vaultList.filter(v => !v.locked)} vault={importFor} typeIcon={TYPE_ICON}
            onClose={() => setImportFor(null)}
            onImport={async (vid, list, doneText) => {
              const res = await run(backend.importItems(vid, null, list));
              if (!res || !apply(res[1])) return false;
              notify(doneText); setVault(vid); setFolder(null);
              return true;
            }} />
        </Suspense>
      )}
      {folderDialog && (
        <FolderDialog t={t} mode={folderDialog.mode} name={folderDialog.name ?? ''} vault={folderDialog.vault ?? targetVault}
          folders={folders} parent={folderDialog.parent ?? (folderDialog.mode === 'create' && folder && folders.some(f => f.id === folder && f.vault === (folderDialog.vault ?? targetVault)) ? folder : '')}
          vaults={vaultList.filter(v => !v.locked)} onClose={() => setFolderDialog(null)}
          onSubmit={async (vid, name, parent) => {
            const res = folderDialog.mode === 'rename'
              ? await run(backend.folderRename(vid, folderDialog.id!, name))
              : await run(backend.folderCreate(vid, parent || null, name));
            if (apply(res)) { setFolderDialog(null); if (folderDialog.mode === 'create') { setVault(vid); setFolder(null); } }
          }} />
      )}
      {vaultDialog && (
        <VaultDialog t={t} known={known} initialPath={vaultDialog.path} modal
          onClose={() => setVaultDialog(null)}
          onOpened={(d, meta) => { onOpened(d, meta); setVaultDialog(null); setVault(d.id); setFolder(null); }} />
      )}
      {keyDialog && <KeyDialog t={t} onClose={() => setKeyDialog(null)}
        onSubmit={async pw => { if ((await run(backend.changeKey(keyDialog, pw))) !== undefined) { setKeyDialog(null); notify(t.masterKeyChanged); } }} />}
      {confirm && (
        <div className="scrim" onClick={() => setConfirm(null)}>
          <div className="dialog" role="alertdialog" aria-label={confirm.title} onClick={e => e.stopPropagation()}>
            <h3><Icon n={confirm.icon} />{confirm.title}</h3>
            <p className="dialog-body">{confirm.body}</p>
            <div className="row">
              <button className="btn text" onClick={() => setConfirm(null)}>{t.cancel}</button>
              <button className="btn filled" onClick={() => { confirm.action(); setConfirm(null); }}><Icon n={confirm.icon} />{confirm.label}</button>
            </div>
          </div>
        </div>
      )}
      {snackbar}
    </div>
  );
}

// rawToItem per raw object, so unchanged entries keep identity across vault refreshes
const itemCache = new WeakMap<object, Item>();
function rawToItemCached(r: VaultData['items'][number], v: VaultData): Item {
  let i = itemCache.get(r);
  if (!i) { i = rawToItem(r, v); itemCache.set(r, i); }
  return i;
}

function FolderDialog({ t, mode, name: initialName, vault: initialVault, vaults, folders, parent: initialParent, onClose, onSubmit }: {
  t: Strings; mode: 'create' | 'rename'; name: string; vault: string; vaults: VaultInfo[]; folders: Folder[]; parent: string;
  onClose: () => void; onSubmit: (vault: string, name: string, parent: string) => void;
}) {
  const [name, setName] = useState(initialName);
  const [vault, setVault] = useState(initialVault);
  const [parent, setParent] = useState(initialParent);
  const options = folders.filter(f => f.vault === vault);
  return (
    <div className="scrim" onClick={onClose}>
      <form className="dialog" role="dialog" aria-label={mode === 'create' ? t.newFolder : t.renameFolder} onClick={e => e.stopPropagation()}
        onSubmit={e => { e.preventDefault(); if (name.trim()) onSubmit(vault, name.trim(), parent); }}>
        <h3><Icon n={mode === 'create' ? 'create_new_folder' : 'drive_file_rename_outline'} />{mode === 'create' ? t.newFolder : t.renameFolder}</h3>
        <label className="textfield">
          <Icon n="folder" />
          <input autoFocus placeholder={t.folderName} aria-label={t.folderName} value={name} onChange={e => setName(e.target.value)} />
        </label>
        {mode === 'create' && vaults.length > 1 && (
          <>
            <span className="label">{t.vault}</span>
            <div className="choices">
              {vaults.map(v => (
                <button type="button" key={v.id} className={'choice' + (vault === v.id ? ' on' : '')} onClick={() => { setVault(v.id); setParent(''); }}>
                  {v.name}{vault === v.id && <Icon n="check_circle" fill />}
                </button>
              ))}
            </div>
          </>
        )}
        {mode === 'create' && options.length > 0 && (
          <label className="opt">{t.parentFolder}
            <select className="set-select" value={parent} onChange={e => setParent(e.target.value)}>
              <option value="">{vaults.find(v => v.id === vault)?.name ?? '—'}</option>
              {options.map(f => <option key={f.id} value={f.id}>{f.name}</option>)}
            </select>
          </label>
        )}
        <div className="row">
          <button type="button" className="btn text" onClick={onClose}>{t.cancel}</button>
          <button type="submit" className="btn filled" disabled={!name.trim()}><Icon n="check" />{mode === 'create' ? t.create : t.rename}</button>
        </div>
      </form>
    </div>
  );
}

const SHORTCUTS: [string, keyof Strings][] = [
  ['Ctrl+F', 'scSearch'], ['Ctrl+N', 'scNew'], ['Ctrl+E', 'scEdit'], ['Ctrl+B', 'scCopyUser'], ['Ctrl+C', 'scCopyPw'],
  ['Ctrl+T', 'scCopyTotp'], ['Ctrl+U', 'scOpenUrl'], ['Ctrl+D', 'scDuplicate'], ['Ctrl+Shift+V', 'autoType'], ['Entf / Del', 'scTrash'],
  ['↑ ↓', 'scNavigate'], ['Esc', 'scCancel'], ['Ctrl+L', 'scLock'], ['F1', 'scHelp'],
];

function ShortcutsDialog({ t, onClose }: { t: Strings; onClose: () => void }) {
  return createPortal(
    <div className="scrim" onClick={onClose}>
      <div className="dialog" role="dialog" aria-label={t.shortcuts} onClick={e => e.stopPropagation()}>
        <h3><Icon n="keyboard" />{t.shortcuts}</h3>
        <dl className="shortcut-list">
          {SHORTCUTS.map(([keys, label]) => (
            <div key={keys}><dt><kbd>{keys}</kbd></dt><dd>{t[label]}</dd></div>
          ))}
        </dl>
        <small className="label">{t.dragHint}</small>
        <div className="row"><button className="btn filled" onClick={onClose}>{t.close}</button></div>
      </div>
    </div>, document.body);
}

/** Confirmations the browser extension needs: new connection, access to logins, updating a login. */
function BrowserAskDialog({ t, ask, vaultName, onAnswer }: {
  t: Strings; ask: BrowserAsk; vaultName: (id: string) => string; onAnswer: (answer: unknown) => void;
}) {
  const [name, setName] = useState('browser-' + new Date().toISOString().slice(0, 10));
  const [allow, setAllow] = useState<string[]>(ask.kind === 'access' ? ask.entries.map(e => e.uuid) : []);
  const [remember, setRemember] = useState(true);
  const [target, setTarget] = useState<string | null>(null); // passkey: entry to update / to sign in with
  const deny = () => onAnswer(null);
  return createPortal(
    <div className="scrim">
      <div className="dialog browser-ask" role="alertdialog" aria-label={t.brAccessTitle}
        onKeyDown={e => { if (e.key === 'Escape') { e.stopPropagation(); deny(); } }}>
        {ask.kind === 'associate' && (
          <form onSubmit={e => { e.preventDefault(); if (name.trim()) onAnswer({ name: name.trim() }); }} className="browser-ask-form">
            <h3><Icon n="extension" />{t.brAssocTitle}</h3>
            <p className="dialog-body">{t.brAssocBody}</p>
            <label className="textfield"><Icon n="badge" />
              <input autoFocus value={name} onChange={e => setName(e.target.value)} aria-label={t.brAssocName} placeholder={t.brAssocName} />
            </label>
            <div className="row">
              <button type="button" className="btn text" onClick={deny}>{t.brDeny}</button>
              <button type="submit" className="btn filled" disabled={!name.trim()}><Icon n="link" />{t.brAllowSave}</button>
            </div>
          </form>
        )}
        {ask.kind === 'access' && (
          <>
            <h3><Icon n="travel_explore" />{t.brAccessTitle}</h3>
            <p className="dialog-body">{t.brAccessBody} <b>{ask.host}</b></p>
            <div className="browser-ask-list">
              {ask.entries.map(e => (
                <label key={e.uuid} className="opt">
                  <span className="browser-ask-entry"><b>{e.title || t.untitled}</b><small>{[e.username, vaultName(e.vault)].filter(Boolean).join(' · ')}</small></span>
                  <input className="switch" type="checkbox" checked={allow.includes(e.uuid)}
                    onChange={ev => setAllow(a => ev.target.checked ? [...a, e.uuid] : a.filter(x => x !== e.uuid))} />
                </label>
              ))}
            </div>
            <label className="opt">{t.brRemember}<input className="switch" type="checkbox" checked={remember} onChange={e => setRemember(e.target.checked)} /></label>
            <div className="row">
              <button className="btn text" onClick={() => onAnswer({ allow: [], remember })}>{t.brDeny}</button>
              <button className="btn filled" autoFocus onClick={() => onAnswer({ allow, remember })}><Icon n="check" />{t.brAllow}</button>
            </div>
          </>
        )}
        {ask.kind === 'passkeyRegister' && (
          <>
            <h3><Icon n="passkey" />{t.pkRegTitle}</h3>
            <p className="dialog-body">{t.pkRegBody} <b>{ask.rpId}</b>{ask.username && <> ({ask.username})</>}</p>
            {ask.existing.length > 0 && (
              <div className="browser-ask-list">
                {[{ uuid: '', title: t.pkRegNew, username: '', vault: '' }, ...ask.existing].map(e => (
                  <label key={e.uuid || 'new'} className="opt">
                    <span className="browser-ask-entry"><b>{e.uuid ? `${t.pkRegReplace} ${e.title || t.untitled}` : e.title}</b>
                      <small>{[e.username, e.vault && vaultName(e.vault)].filter(Boolean).join(' · ')}</small></span>
                    <input type="radio" name="pk-target" checked={(target ?? '') === e.uuid} onChange={() => setTarget(e.uuid)} />
                  </label>
                ))}
              </div>
            )}
            <div className="row">
              <button className="btn text" onClick={deny}>{t.cancel}</button>
              <button className="btn filled" autoFocus onClick={() => onAnswer({ ok: true, uuid: target || null })}><Icon n="check" />{t.pkSave}</button>
            </div>
          </>
        )}
        {ask.kind === 'passkeyGet' && (
          <>
            <h3><Icon n="passkey" />{t.pkGetTitle}</h3>
            <p className="dialog-body">{t.pkGetBody} <b>{ask.rpId}</b></p>
            <div className="browser-ask-list">
              {ask.entries.map(e => (
                <label key={e.uuid} className="opt">
                  <span className="browser-ask-entry"><b>{e.title || t.untitled}</b><small>{[e.username, vaultName(e.vault)].filter(Boolean).join(' · ')}</small></span>
                  <input type="radio" name="pk-pick" checked={(target ?? ask.entries[0]?.uuid) === e.uuid} onChange={() => setTarget(e.uuid)} />
                </label>
              ))}
            </div>
            <div className="row">
              <button className="btn text" onClick={deny}>{t.cancel}</button>
              <button className="btn filled" autoFocus onClick={() => onAnswer({ uuid: target ?? ask.entries[0]?.uuid })}><Icon n="login" />{t.pkUse}</button>
            </div>
          </>
        )}
        {ask.kind === 'update' && (
          <>
            <h3><Icon n="sync_lock" />{t.brUpdateTitle}</h3>
            <p className="dialog-body">{t.brUpdateBody}: <b>{ask.title || t.untitled}</b>{ask.username && <> ({ask.username})</>}</p>
            <div className="row">
              <button className="btn text" onClick={deny}>{t.cancel}</button>
              <button className="btn filled" autoFocus onClick={() => onAnswer({ ok: true })}><Icon n="check" />{t.brUpdate}</button>
            </div>
          </>
        )}
      </div>
    </div>, document.body);
}

/** Entry choice for a global Auto-Type: matches first, otherwise search all entries. */
function AutoTypePicker({ t, pick, items, vaultName, onPick, onClose }: {
  t: Strings; pick: AutoTypePick; items: Item[]; vaultName: (id: string) => string;
  onPick: (vault: string, id: string, sequence: string | null) => void; onClose: () => void;
}) {
  const [q, setQ] = useState('');
  const query = q.trim().toLowerCase();
  const rows = pick.candidates.length && !query
    ? pick.candidates.map(c => ({ vault: c.vault, id: c.id, title: c.title, sub: c.username, sequence: c.sequence as string | null }))
    : items.filter(i => !query || (i.title + ' ' + i.subtitle).toLowerCase().includes(query)).slice(0, 50)
      .map(i => ({ vault: i.vault, id: i.id, title: i.title, sub: i.subtitle, sequence: null }));
  return createPortal(
    <div className="scrim" onClick={onClose}>
      <div className="dialog autotype-dialog" role="dialog" aria-label={t.autoType} onClick={e => e.stopPropagation()}>
        <h3><Icon n="keyboard" />{t.autoTypePick}</h3>
        <p className="dialog-body autotype-window" title={pick.windowTitle}>{pick.windowTitle || '—'}</p>
        {!pick.candidates.length && <small className="label">{t.autoTypeNone}</small>}
        <label className="textfield">
          <Icon n="search" />
          <input autoFocus placeholder={t.search} aria-label={t.search} value={q} onChange={e => setQ(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && rows[0]) onPick(rows[0].vault, rows[0].id, rows[0].sequence); }} />
        </label>
        <div className="autotype-list">
          {rows.map(r => (
            <button key={r.vault + r.id} className="item" onClick={() => onPick(r.vault, r.id, r.sequence)}>
              <span className="avatar login"><Icon n="person" /></span>
              <span><b>{r.title || t.untitled}</b><span>{[r.sub, vaultName(r.vault)].filter(Boolean).join(' · ')}</span></span>
            </button>
          ))}
          {!rows.length && <div className="empty"><Icon n="eco" />{t.noItems}</div>}
        </div>
        <div className="row"><button className="btn text" onClick={onClose}>{t.cancel}</button></div>
      </div>
    </div>, document.body);
}

/** Free tags; Enter or comma adds, Backspace on empty input removes the last one. */
function TagEditor({ t, tags, onChange }: { t: Strings; tags: string[]; onChange: (tags: string[]) => void }) {
  const [text, setText] = useState('');
  const add = () => {
    const v = text.trim().replace(/[,;]/g, '');
    if (v && !tags.includes(v) && v !== 'pinned') onChange([...tags, v]);
    setText('');
  };
  return (
    <div className="field tag-editor">
      <Icon n="sell" />
      <div>
        <span className="label">{t.tags}</span>
        <div className="tag-input">
          {tags.map(tg => (
            <span key={tg} className="badge tag">{tg}
              <button type="button" onClick={() => onChange(tags.filter(x => x !== tg))} aria-label={`${t.remove}: ${tg}`}><Icon n="close" /></button>
            </span>
          ))}
          <input value={text} placeholder={t.addTag} aria-label={t.addTag} onChange={e => setText(e.target.value)} onBlur={add}
            onKeyDown={e => {
              if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); add(); }
              else if (e.key === 'Backspace' && !text && tags.length) onChange(tags.slice(0, -1));
            }} />
        </div>
      </div>
    </div>
  );
}

function KeyDialog({ t, onClose, onSubmit }: { t: Strings; onClose: () => void; onSubmit: (pw: string) => void }) {
  const [pw, setPw] = useState('');
  const [confirm, setConfirm] = useState('');
  const mismatch = confirm.length > 0 && pw !== confirm;
  return (
    <div className="scrim" onClick={onClose}>
      <form className="dialog" role="dialog" aria-label={t.changeMasterKey} onClick={e => e.stopPropagation()}
        onSubmit={e => { e.preventDefault(); if (pw && pw === confirm) onSubmit(pw); }}>
        <h3><Icon n="key" />{t.changeMasterKey}</h3>
        <label className="textfield"><Icon n="key" />
          <input type="password" autoFocus placeholder={t.masterPassword} aria-label={t.masterPassword} value={pw} onChange={e => setPw(e.target.value)} />
        </label>
        <PasswordStrength t={t} password={pw} breachCheck />
        <label className="textfield"><Icon n="key" />
          <input type="password" placeholder={t.confirmPassword} aria-label={t.confirmPassword} value={confirm} onChange={e => setConfirm(e.target.value)} />
        </label>
        {mismatch && <p className="form-error" role="alert"><Icon n="error" />{t.passwordsDontMatch}</p>}
        <div className="row">
          <button type="button" className="btn text" onClick={onClose}>{t.cancel}</button>
          <button type="submit" className="btn filled" disabled={!pw || pw !== confirm}><Icon n="check" />{t.save}</button>
        </div>
      </form>
    </div>
  );
}

function NavItem(p: {
  active: boolean; onClick: () => void; icon: string; bg: string; name: string; sub?: string; count?: number; locked?: boolean;
  drop?: Pick<React.HTMLAttributes<HTMLButtonElement>, 'onDragOver' | 'onDragLeave' | 'onDrop'>; over?: boolean;
  onContextMenu?: (e: React.MouseEvent) => void;
}) {
  return (
    <button className={'nav-item' + (p.active ? ' active' : '') + (p.locked ? ' locked' : '') + (p.over ? ' drop-over' : '')}
      onClick={p.onClick} title={p.sub ? `${p.name} · ${p.sub}` : p.name} {...p.drop} onContextMenu={p.onContextMenu}>
      <span className="vi" style={{ background: `var(${p.bg})`, color: p.bg.startsWith('--v-') ? 'var(--v-on)' : 'inherit' }}>
        <Icon n={p.icon} fill={p.active} />
      </span>
      <span>{p.name}{p.sub && <small>{p.sub}</small>}</span>
      <span className="count">{p.count}</span>
    </button>
  );
}

const isExpired = (i: Item) => !!i.expires && i.expires < today();

/** Type avatar, or the entry's website/custom icon on a soft tile. */
function ItemAvatar({ item }: { item: Item }) {
  return item.icon
    ? <span className="avatar favicon"><img src={item.icon} alt="" draggable={false} /></span>
    : <span className={'avatar ' + item.type}><Icon n={TYPE_ICON[item.type]} /></span>;
}

/** Any image the webview can decode → 64×64 PNG (base64), what KeePass clients expect. */
function toPng(b64: string): Promise<string | null> {
  return new Promise(resolve => {
    const img = new Image();
    img.onload = () => {
      const c = document.createElement('canvas');
      c.width = c.height = 64;
      const ctx = c.getContext('2d');
      if (!ctx || !img.width) return resolve(null);
      ctx.imageSmoothingQuality = 'high';
      ctx.drawImage(img, 0, 0, 64, 64);
      resolve(c.toDataURL('image/png').split(',')[1] ?? null);
    };
    img.onerror = () => resolve(null);
    img.src = iconUrl(b64);
  });
}

function Row({ t, item, active, onClick, dragRef, onDragEnd, onContextMenu }: {
  t: Strings; item: Item; active: boolean; onClick: () => void;
  dragRef: React.MutableRefObject<Item | null>; onDragEnd: () => void; onContextMenu: (e: React.MouseEvent) => void;
}) {
  const saved = !item.id.startsWith('new:');
  return (
    <button className={'item' + (active ? ' active' : '')} onClick={onClick} onContextMenu={onContextMenu} draggable={saved}
      onDragStart={e => { dragRef.current = item; e.dataTransfer.effectAllowed = 'move'; e.dataTransfer.setData('text/plain', item.title); }}
      onDragEnd={() => { dragRef.current = null; onDragEnd(); }}>
      <ItemAvatar item={item} />
      <span><b>{item.title || t.untitled}</b><span>{item.subtitle || t[item.type]}</span></span>
      {isExpired(item) ? <span className="pin expired" title={t.expired}><Icon n="event_busy" /></span>
        : item.pinned && <span className="pin"><Icon n="push_pin" fill /></span>}
    </button>
  );
}

const KIND_ICON: Record<FieldKind, string> = {
  text: 'short_text', hidden: 'visibility_off', totp: 'lock_clock', date: 'calendar_month', url: 'language',
};
const ADDABLE: { kind: FieldKind; name: keyof Strings }[] = [
  { kind: 'text', name: 'fieldText' },
  { kind: 'totp', name: 'fieldTotp' },
  { kind: 'hidden', name: 'fieldHidden' },
  { kind: 'date', name: 'fieldDate' },
];

const fieldName = (t: Strings, f: Field) => (f.key ? t[f.key] : f.label) || t.fieldText;
const fieldIcon = (f: Field) => (f.key && FIELD_ICON[f.key]) || KIND_ICON[f.kind ?? 'text'];
const isSecret = (f: Field) => f.kind === 'hidden' || f.kind === 'totp';
const fmtSize = (n: number) => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
const fmtDate = (iso: string) => new Date(iso.length > 10 ? iso : iso + 'T00:00').toLocaleDateString(document.documentElement.lang);

/** Polls the backend for the current TOTP code while `enabled`. */
function useTotp(get: (() => Promise<Totp>) | undefined, enabled: boolean) {
  const [s, setS] = useState<Totp | null>(null);
  const getRef = useRef(get);
  getRef.current = get;
  useEffect(() => {
    if (!enabled || !getRef.current) return;
    let live = true;
    const tick = () => getRef.current?.().then(v => live && setS(v)).catch(() => live && setS(null));
    tick();
    const id = setInterval(tick, 1000);
    return () => { live = false; clearInterval(id); };
  }, [enabled]);
  return s;
}

function FieldRow({ t, f, prefs, onCopy, reveal, totp, onEdit }: {
  t: Strings; f: Field; prefs: Prefs; onCopy: () => void; onEdit: () => void;
  reveal?: () => Promise<string>; totp?: () => Promise<Totp>;
}) {
  const isPw = f.key === 'password';
  const isNote = f.key === 'noteBody';
  // which fields start masked in the preview (reveal via eye button)
  const maskable = f.kind === 'hidden' || (f.kind === 'totp' && prefs.hideTotpPreview) || (isNote && prefs.hideNotesPreview);
  const [shown, setShown] = useState(() => f.kind === 'hidden' ? isPw && !prefs.hidePwPreview : !maskable);
  // protected values are fetched from the backend only when shown
  const [secret, setSecret] = useState<string | null>(f.protected && !f.loaded && f.kind !== 'totp' ? null : f.value);
  useEffect(() => {
    if (shown && secret === null && reveal) reveal().then(setSecret).catch(() => setSecret(''));
  }, [shown, secret, reveal]);
  // revealed secrets mask themselves again after a while and leave the UI's memory
  useEffect(() => {
    if (!shown || !maskable || !prefs.revealSeconds) return;
    const timer = setTimeout(() => { setShown(false); if (f.protected && !f.loaded) setSecret(null); }, prefs.revealSeconds * 1000);
    return () => clearTimeout(timer);
  }, [shown, maskable, prefs.revealSeconds, f.protected, f.loaded]);
  const otp = useTotp(totp, f.kind === 'totp' && !(maskable && !shown));
  const openMenu = useContextMenu();
  const menu = (e: React.MouseEvent) => openMenu(e, [
    { icon: 'content_copy', label: t.copy, action: onCopy },
    ...(maskable ? [{ icon: shown ? 'visibility_off' : 'visibility', label: shown ? t.hide : t.show, action: () => setShown(s => !s) }] : []),
    ...(f.kind === 'url' && f.value ? [{ icon: 'open_in_new', label: t.scOpenUrl, action: () => openExternal(f.value) }] : []),
    'sep',
    { icon: 'edit', label: t.edit, kbd: 'Ctrl+E', action: onEdit },
  ]);
  const name = fieldName(t, f);
  const masked = maskable && !shown;
  const value = secret ?? '';
  const urlAction = () => {
    if (prefs.urlDoubleClick === 'open') openExternal(f.value);
    else if (prefs.urlDoubleClick === 'edit') onEdit();
    else onCopy();
  };
  const code = otp?.code ?? '';
  const val =
    isPw && secret === '' ? (prefs.passwordPlaceholder ? '••••••••' : '')
    : f.kind === 'url' ? <a href={f.value} target="_blank" rel="noreferrer" onClick={e => { e.stopPropagation(); e.preventDefault(); openExternal(f.value); }}>{f.value}</a>
    : f.kind === 'totp' ? (
      <span className="otp">
        {masked ? '••• •••' : code ? `${code.slice(0, Math.ceil(code.length / 2))} ${code.slice(Math.ceil(code.length / 2))}` : '— — —'}
        {otp && !masked && <i className="ring" style={{ '--p': otp.remaining / otp.period } as React.CSSProperties}>{otp.remaining}</i>}
      </span>
    )
    : masked || secret === null ? '••••••••'
    : f.kind === 'hidden' && prefs.colorizePasswords ? colorize(value)
    : f.kind === 'date' && value ? fmtDate(value)
    : value;
  const mono = isSecret(f) || (isNote && prefs.monospaceNotes);
  const multi = f.key && MULTILINE.has(f.key);
  return (
    // whole row copies (click or double-click per settings); inner controls stop propagation
    <div className="field copyable" role="button" tabIndex={0} title={prefs.copyOnDoubleClick ? undefined : t.clickToCopy}
      aria-label={`${t.copy}: ${name}`} onContextMenu={menu}
      onClick={prefs.copyOnDoubleClick ? undefined : onCopy}
      onDoubleClick={f.kind === 'url' ? urlAction : prefs.copyOnDoubleClick ? onCopy : undefined}
      onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onCopy(); } }}>
      <Icon n={fieldIcon(f)} />
      <div>
        <span className="label">{name}</span>
        <div className={'val' + (mono ? ' mono' : '') + (multi ? ' multi' : '')}
          title={!multi && !isSecret(f) && typeof val === 'string' ? val : undefined}>{val}</div>
      </div>
      <div className="tools">
        {maskable && (
          <button className="icon-btn" title={shown ? t.hide : t.show} aria-label={shown ? t.hide : t.show}
            onClick={e => { e.stopPropagation(); setShown(s => !s); }}
            onDoubleClick={e => e.stopPropagation()} onKeyDown={e => e.stopPropagation()}>
            <Icon n={shown ? 'visibility_off' : 'visibility'} />
          </button>
        )}
        <span className="copy-hint" aria-hidden><Icon n="content_copy" /></span>
      </div>
    </div>
  );
}

function EditRow({ t, f, prefs, title, onChange, onRemove, onCopy }: {
  t: Strings; f: Field; prefs: Prefs; title: string; onChange: (f: Field) => void; onRemove?: () => void;
  onCopy: (text: string, what: string) => void;
}) {
  const [shown, setShown] = useState(!prefs.hideInEdit);
  const [gen, setGen] = useState(false);
  const canGenerate = f.key === 'password' || (f.kind === 'hidden' && !f.key);
  const type = f.kind === 'date' ? 'date' : f.kind === 'url' ? 'url' : isSecret(f) && !shown ? 'password' : 'text';
  return (
    <div className="field">
      <Icon n={fieldIcon(f)} />
      <div>
        {f.key ? <span className="label">{t[f.key]}</span> : (
          <input className="label-edit" value={f.label ?? ''} placeholder={t.fieldName} aria-label={t.fieldName}
            onChange={e => onChange({ ...f, label: e.target.value, raw: undefined })} />
        )}
        {f.key && MULTILINE.has(f.key) ? (
          // textarea keeps newlines; <input> would strip them on save
          <textarea className="val edit" rows={4} value={f.value} aria-label={fieldName(t, f)}
            onChange={e => onChange({ ...f, value: e.target.value })} />
        ) : f.kind === 'totp' ? (
          <TotpSetup t={t} value={f.value} title={title} onChange={value => onChange({ ...f, value })}>
            <input className="val edit mono" type={type} value={f.value} aria-label={fieldName(t, f)} placeholder="otpauth://… / JBSWY3DP…"
              autoComplete="off" spellCheck={false} onChange={e => onChange({ ...f, value: e.target.value })} />
          </TotpSetup>
        ) : (
          <input className={'val edit' + (isSecret(f) ? ' mono' : '')} type={type} value={f.value} aria-label={fieldName(t, f)}
            autoComplete="off" spellCheck={false} onChange={e => onChange({ ...f, value: e.target.value })} />
        )}
      </div>
      <div className="tools">
        {canGenerate && (
          <button type="button" className="icon-btn" title={t.genOpen} aria-label={t.genOpen} onClick={() => setGen(true)}>
            <Icon n="password" />
          </button>
        )}
        {gen && <Suspense fallback={null}><Generator t={t} onClose={() => setGen(false)} onCopy={onCopy} onUse={(pw: string) => onChange({ ...f, value: pw })} /></Suspense>}
        {isSecret(f) && !(f.key && MULTILINE.has(f.key)) && (
          <button type="button" className="icon-btn" aria-label={shown ? t.hide : t.show} onClick={() => setShown(s => !s)}>
            <Icon n={shown ? 'visibility_off' : 'visibility'} />
          </button>
        )}
        {onRemove && (
          <button type="button" className="icon-btn" title={t.remove} aria-label={t.remove} onClick={onRemove}>
            <Icon n="delete" />
          </button>
        )}
      </div>
    </div>
  );
}

function Detail({ t, item, vault: v, folders, isNew, prefs, onCopyField, onCopyText, loadSecrets, getTotp, onDuplicate, onSave, onDiscard,
  onTrash, onRestore, onDeleteForever, onTogglePin, onHistoryRestore, onDownload, onLoadIcon, onRemoveIcon, onSshChanged, onMessage }: {
  t: Strings; item: Item; vault: VaultInfo; folders: Folder[]; isNew: boolean; prefs: Prefs;
  onCopyField: (f: Field, what: string) => void; onCopyText: (text: string, what: string) => void;
  loadSecrets: () => Promise<Record<string, string>>; getTotp: (field: string) => Promise<Totp>; onDuplicate: () => void;
  onSave: (d: Draft) => Promise<boolean>; onDiscard: () => void;
  onTrash: () => void; onRestore: () => void; onDeleteForever: () => void; onTogglePin: () => void;
  onHistoryRestore: (index: number) => void; onDownload: (a: Attachment) => void;
  onLoadIcon?: () => void; onRemoveIcon?: () => void;
  onSshChanged?: (d: VaultData) => void; onMessage: (msg: string, error?: boolean) => void;
}) {
  const [moreMenu, setMoreMenu] = useState(false);
  const fromItem = (): Draft => ({
    title: item.title, folder: item.folder ?? '', note: item.note ?? '', expires: item.expires ?? null, tags: item.tags ?? [],
    fields: item.fields.map(f => ({ ...f })), attachments: item.attachments ?? [],
  });
  const [draft, setDraft] = useState<Draft | null>(() => isNew ? fromItem() : null); // non-null = edit mode
  const [busy, setBusy] = useState(false);
  const [menu, setMenu] = useState(false);
  const [dragging, setDragging] = useState(false);
  const d = draft ?? fromItem();
  const folderName = folders.find(f => f.id === item.folder)?.name;
  const ms = settingsStrings[prefs.lang].ui;

  // reveal one protected field (cached per detail view)
  const secrets = useRef<Promise<Record<string, string>> | null>(null);
  const getSecrets = () => {
    if (!secrets.current) {
      secrets.current = loadSecrets();
      setTimeout(() => { secrets.current = null; }, 30_000); // don't keep decrypted values around
    }
    return secrets.current;
  };
  const revealer = (raw: string) => () => getSecrets().then(s => s[raw] ?? '');

  const startEdit = async () => {
    const next = fromItem();
    if (next.fields.some(f => f.protected)) {
      const s = await getSecrets();
      next.fields = next.fields.map(f => f.protected && f.raw ? { ...f, value: s[f.raw] ?? '', loaded: true } : f);
    }
    setDraft(next);
  };
  const save = async () => {
    setBusy(true);
    const ok = await onSave(draft!);
    setBusy(false);
    if (ok && !isNew) { secrets.current = null; setDraft(null); }
  };
  const cancel = () => { setMenu(false); if (isNew) onDiscard(); else setDraft(null); };
  const keys = useRef({ startEdit: () => {}, cancel: () => {}, editing: false, trashed: false });
  keys.current = { startEdit, cancel, editing: !!draft, trashed: !!item.trashed };
  useEffect(() => {
    const edit = () => { if (!keys.current.editing && !keys.current.trashed) keys.current.startEdit(); };
    const esc = () => { if (keys.current.editing) keys.current.cancel(); };
    window.addEventListener('akp:edit', edit);
    window.addEventListener('akp:cancel', esc);
    return () => { window.removeEventListener('akp:edit', edit); window.removeEventListener('akp:cancel', esc); };
  }, []);
  const patch = (p: Partial<Draft>) => setDraft(x => ({ ...x!, ...p }));
  const setField = (idx: number, f: Field) => patch({ fields: d.fields.map((x, i) => i === idx ? f : x) });
  const addField = (kind: FieldKind, name: keyof Strings) => {
    patch({ fields: [...d.fields, { label: t[name], value: '', kind }] });
    setMenu(false);
  };
  const addFiles = (files: FileList | null) => {
    if (!files?.length) return;
    patch({ attachments: [...d.attachments, ...[...files].map(f => ({ name: f.name, size: f.size, file: f }))] });
  };
  const viewFields = d.fields.filter(f => f.protected || f.value);
  const expired = !!item.expires && item.expires < today();

  return (
    <>
      <header>
        <div className="hero">
          <ItemAvatar item={item} />
          <div>
            {draft ? (
              <input className="title-edit" value={draft.title} placeholder={t.title} aria-label={t.title} autoFocus={isNew}
                onChange={e => patch({ title: e.target.value })} />
            ) : <h2 title={item.title}>{item.title || t.untitled}</h2>}
            <div className="meta">
              <span className="badge" style={{ background: `var(${v.color})`, color: 'var(--v-on)' }}><Icon n={v.icon} />{v.name}</span>
              {draft ? (
                <label className="badge select">
                  <Icon n="folder" />
                  <select value={draft.folder} onChange={e => patch({ folder: e.target.value })} aria-label={t.folder}>
                    <option value="">{t.noFolder}</option>
                    {folders.map(f => <option key={f.id} value={f.id}>{f.name}</option>)}
                  </select>
                </label>
              ) : folderName && <span className="badge"><Icon n="folder" />{folderName}</span>}
              <span className="badge">{t[item.type]}</span>
              {item.pinned && <span className="badge"><Icon n="push_pin" />{t.pinned}</span>}
              {!draft && item.tags?.map(tg => <span key={tg} className="badge tag"><Icon n="sell" />{tg}</span>)}
              {!draft && item.expires && (
                <span className={'badge' + (expired ? ' danger' : '')}><Icon n={expired ? 'event_busy' : 'event'} />
                  {expired ? t.expired : `${t.expiresOn} ${fmtDate(item.expires)}`}</span>
              )}
              {item.trashed && <span className="badge danger"><Icon n="delete" />{t.trash}</span>}
            </div>
          </div>
        </div>
        <div className="actions">
          {draft ? (
            <>
              <button className="btn text" onClick={cancel}>{t.cancel}</button>
              <button className="btn filled" onClick={save} disabled={busy}><Icon n={busy ? 'hourglass_top' : 'check'} />{t.save}</button>
            </>
          ) : (
            <>
              {item.trashed
                ? <button className="btn filled" onClick={onRestore}><Icon n="restore_from_trash" />{t.restore}</button>
                : <button className="btn filled" onClick={startEdit}><Icon n="edit" />{t.edit}</button>}
              <span className="more-wrap">
                <button className="icon-btn tonal" aria-label={t.more} aria-expanded={moreMenu} onClick={() => setMoreMenu(m => !m)}>
                  <Icon n="more_vert" />
                </button>
                {moreMenu && (
                  <>
                    <div className="menu-scrim" onClick={() => setMoreMenu(false)} />
                    <div className="menu more-menu" role="menu">
                      {!item.trashed && (
                        <button role="menuitem" onClick={() => { setMoreMenu(false); onTogglePin(); }}>
                          <Icon n="push_pin" />{item.pinned ? t.unpinItem : t.pinItem}
                        </button>
                      )}
                      {!item.trashed && (
                        <button role="menuitem" onClick={() => { setMoreMenu(false); onDuplicate(); }}>
                          <Icon n="content_copy" />{t.duplicate}<kbd>Ctrl+D</kbd>
                        </button>
                      )}
                      {!item.trashed && onLoadIcon && (
                        <button role="menuitem" onClick={() => { setMoreMenu(false); onLoadIcon(); }}>
                          <Icon n="image_search" />{t.loadIcon}
                        </button>
                      )}
                      {!item.trashed && onRemoveIcon && (
                        <button role="menuitem" onClick={() => { setMoreMenu(false); onRemoveIcon(); }}>
                          <Icon n="hide_image" />{t.removeIcon}
                        </button>
                      )}
                      {item.trashed ? (
                        <button role="menuitem" onClick={() => { setMoreMenu(false); onDeleteForever(); }}>
                          <Icon n="delete_forever" />{t.deleteForever}
                        </button>
                      ) : (
                        <button role="menuitem" onClick={() => { setMoreMenu(false); onTrash(); }}>
                          <Icon n="delete" />{ms.moveToTrash}
                        </button>
                      )}
                    </div>
                  </>
                )}
              </span>
            </>
          )}
        </div>
      </header>

      {(draft ? d.fields : viewFields).length > 0 && (
        <div className={'fields' + (draft ? ' editing' : '')}>
          {draft
            ? d.fields.map((f, idx) => (
              <EditRow key={idx} t={t} f={f} prefs={prefs} title={d.title} onCopy={onCopyText} onChange={nf => setField(idx, nf)}
                onRemove={f.key ? undefined : () => patch({ fields: d.fields.filter((_, i) => i !== idx) })} />
            ))
            : viewFields.map(f => (
              <FieldRow key={f.raw ?? fieldName(t, f)} t={t} f={f} prefs={prefs} onEdit={startEdit}
                onCopy={() => onCopyField(f, fieldName(t, f))}
                reveal={f.protected && f.raw && !isNew ? revealer(f.raw) : undefined}
                totp={f.kind === 'totp' && !isNew && f.raw ? () => getTotp(f.raw!) : undefined} />
            ))}
        </div>
      )}

      {draft && (
        <div className="add-more">
          <button className="btn text" onClick={() => setMenu(m => !m)} aria-expanded={menu}><Icon n="add" />{t.addMore}</button>
          {menu && (
            <div className="menu" role="menu">
              {ADDABLE.map(a => (
                <button key={a.kind} role="menuitem" onClick={() => addField(a.kind, a.name)}>
                  <Icon n={KIND_ICON[a.kind]} />{t[a.name]}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {draft ? (
        <div className="fields editing section">
          <TagEditor t={t} tags={d.tags} onChange={tags => patch({ tags })} />
          <div className="field">
            <Icon n="sticky_note_2" />
            <div>
              <span className="label">{t.noteBody}</span>
              <textarea className="val edit" rows={3} placeholder={t.addNote} value={d.note}
                onChange={e => patch({ note: e.target.value })} aria-label={t.noteBody} />
            </div>
          </div>
          <div className="field expiry-row">
            <Icon n="event" />
            <div>
              <span className="label">{t.expiry}</span>
              <input className="val edit" type="date" value={d.expires ?? ''} disabled={d.expires === null}
                onChange={e => patch({ expires: e.target.value || null })} aria-label={t.expiresOn} />
            </div>
            <input className="switch" type="checkbox" checked={d.expires !== null} aria-label={t.expiry}
              onChange={e => patch({ expires: e.target.checked ? new Date(Date.now() + 90 * 86_400_000).toISOString().slice(0, 10) : null })} />
          </div>
        </div>
      ) : d.note && (
        <div className="fields section">
          <FieldRow t={t} f={{ key: 'noteBody', value: d.note, raw: 'Notes' }} prefs={prefs} onEdit={startEdit}
            onCopy={() => onCopyField({ key: 'noteBody', value: d.note, raw: 'Notes' }, t.noteBody)} />
        </div>
      )}

      {(draft || d.attachments.length > 0) && (
        <div className="attach section">
          <div className="attach-head">
            <Icon n="attach_file" />
            <div><b>{t.attachments}</b>{draft && <small>{t.attachmentsHint}</small>}</div>
          </div>
          {d.attachments.map((a, idx) => (
            <div className="file-row" key={idx}>
              <Icon n="description" />
              <span><b>{a.name}</b><small>{fmtSize(a.size)}</small></span>
              <button className="icon-btn" title={t.download} aria-label={t.download} onClick={() => onDownload(a)}><Icon n="download" /></button>
              {draft && (
                <button className="icon-btn" title={t.remove} aria-label={t.remove}
                  onClick={() => patch({ attachments: d.attachments.filter((_, i) => i !== idx) })}>
                  <Icon n="delete" />
                </button>
              )}
            </div>
          ))}
          {draft && (
            <label className={'dropzone' + (dragging ? ' over' : '')}
              onDragOver={e => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={e => { e.preventDefault(); setDragging(false); addFiles(e.dataTransfer.files); }}>
              <Icon n="upload" />{t.dropFiles}
              <input type="file" multiple hidden onChange={e => { addFiles(e.target.files); e.target.value = ''; }} />
            </label>
          )}
        </div>
      )}

      {!draft && !isNew && onSshChanged && d.attachments.length > 0 && (
        <SshPanel t={t} vault={item.vault} id={item.id} files={d.attachments.map(a => a.name)} onChanged={onSshChanged} onMessage={onMessage} />
      )}

      {!isNew && (
        <details className="more">
          <summary><Icon n="info" />{t.moreInfo}<Icon n="expand_more" /></summary>
          <dl>
            <dt>{t.modified}</dt><dd>{item.modified ? fmtDate(item.modified) : '—'}</dd>
            <dt>{t.file}</dt><dd title={v.id}>{v.file}</dd>
            <dt>UUID</dt><dd className="mono">{item.id}</dd>
          </dl>
          <div className="history">
            <span className="label">{t.history}</span>
            {!item.history?.length && <small>{t.noHistory}</small>}
            {item.history?.map((when, i) => (
              <div className="history-row" key={i}>
                <Icon n="history" />
                <span>{when ? new Date(when).toLocaleString(document.documentElement.lang) : '—'}</span>
                <button className="btn text" onClick={() => onHistoryRestore(i)}>{t.restoreVersion}</button>
              </div>
            ))}
          </div>
        </details>
      )}
    </>
  );
}

function Setup({ onDone }: { onDone: (s: { lang: Lang; theme: Theme }) => void }) {
  const [step, setStep] = useState(0);
  const [lang, setLang] = useState<Lang>('en');
  const [theme, setTheme] = useState<Theme>('dark');
  const t = strings[lang];

  // live preview of the choices while in setup
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.lang = lang;
  }, [theme, lang]);

  return (
    <div className="center">
      <div className="sheet">
        <div className="steps"><i className="on" /><i className={step === 1 ? 'on' : ''} /></div>
        <div className="logo"><Icon n="encrypted" fill /></div>
        <h1>{t.welcome} <span>✦</span></h1>
        <p>{t.setupIntro}</p>

        {step === 0 ? (
          <>
            <span className="label">{t.language}</span>
            <div className="choices">
              {LANGS.map(l => (
                <button key={l.id} className={'choice' + (lang === l.id ? ' on' : '')} onClick={() => setLang(l.id)}>
                  {l.name}{lang === l.id && <Icon n="check_circle" fill />}
                </button>
              ))}
            </div>
            <div className="row"><span /><button className="btn filled" onClick={() => setStep(1)}>{t.continue}<Icon n="arrow_forward" /></button></div>
          </>
        ) : (
          <>
            <span className="label">{t.appearance}</span>
            <div className="choices">
              {(['dark', 'light'] as const).map(th => (
                <button key={th} className={'choice theme-tile' + (theme === th ? ' on' : '')} onClick={() => setTheme(th)}>
                  <span className={'preview ' + th}><i /><i /></span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Icon n={th === 'dark' ? 'dark_mode' : 'light_mode'} />{t[th]}
                  </span>
                </button>
              ))}
            </div>
            <div className="row">
              <button className="btn text" onClick={() => setStep(0)}><Icon n="arrow_back" />{t.back}</button>
              <button className="btn filled" onClick={() => onDone({ lang, theme })}>{t.finish}<Icon n="arrow_forward" /></button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

