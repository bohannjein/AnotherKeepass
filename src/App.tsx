import { lazy, useState, useCallback, useEffect, useRef, useMemo, Suspense } from 'react';
import { createPortal } from 'react-dom';
import { backend, type VaultData } from './backend';
import { type ItemType, type Field, type Item, type Folder, type VaultInfo, type Draft, draftToInput, rawToItem } from './model';
import { DEMO_VAULTS } from './mock';
import { openOptions, openExternal } from './open';
import { clearHistory, generate } from './generator';
import { type Strings, strings } from './i18n';
import { type Prefs, mergePrefs, DEFAULTS } from './settings';
import { settingsStrings } from './i18n-settings';
import VaultDialog, { type Known } from './VaultDialog';
import { Icon } from './Icon';
import { VaultSettingsDialog } from './VaultSettingsDialog';
import { ExportDialog, MergeDialog, AttachmentPreview } from './TransferDialogs';
import { type PaletteItem, CommandPalette } from './CommandPalette';
import { sortItems, type SortMode, groupItems, type GroupMode } from './listGroups';
import { ShareDialog } from './ShareDialog';
import { HealthRow, HealthOverview } from './HealthOverview';
import { ContextMenuProvider, useContextMenu, type MenuItem } from './ContextMenu';
import { Setup } from './Setup';
import { today, TYPE_ICON, fileName, isRemote, ISSUES, ISSUE_ICON } from './ui';
import { Row, NavItem } from './ItemList';
import { Detail, Generator } from './Detail';
import { useSnack } from './useSnack';
import { useItemActions, type Confirm } from './useItemActions';
import { useHealth } from './useHealth';
import { useDesktopEvents } from './useDesktopEvents';
import { ConfirmDialog, SyncDialog, ShortcutsDialog, BrowserAskDialog, AutoTypePicker, VaultLookDialog, FolderDialog, KeyDialog } from './Dialogs';

// rarely needed views load on first use (keeps startup lean)
const SettingsPage = lazy(() => import('./SettingsPage'));
const ImportDialog = lazy(() => import('./ImportDialog'));
type Settings = Prefs;

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
/** extra entry layouts built from custom fields (labels in the user's language at creation time) */
const TEMPLATE_PRESETS: { id: string; type: ItemType; icon: string; label: 'tplWifi' | 'tplLicense' | 'tplBank' | 'tplServer'; fields: (t: Strings) => Field[] }[] = [
  { id: 'wifi', type: 'other', icon: 'wifi', label: 'tplWifi', fields: t => [{ label: t.fSsid, value: '' }, { key: 'password', value: '', kind: 'hidden' }, { label: t.fSecurity, value: 'WPA2/WPA3' }] },
  { id: 'license', type: 'other', icon: 'license', label: 'tplLicense', fields: t => [{ label: t.fProduct, value: '' }, { label: t.fLicenseKey, value: '', kind: 'hidden', protected: true }, { key: 'email', value: '' }, { label: t.fVersion, value: '' }] },
  { id: 'bank', type: 'other', icon: 'account_balance', label: 'tplBank', fields: t => [{ label: t.fHolder, value: '' }, { label: t.fIban, value: '' }, { label: t.fBic, value: '' }, { key: 'username', value: '' }, { key: 'password', value: '', kind: 'hidden' }, { key: 'pin', value: '', kind: 'hidden' }] },
  { id: 'server', type: 'login', icon: 'dns', label: 'tplServer', fields: t => [{ label: t.fHost, value: '' }, { label: t.fPort, value: '22' }, { key: 'username', value: '' }, { key: 'password', value: '', kind: 'hidden' }, { key: 'website', value: '', kind: 'url' }] },
];

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
  'bCustomProxy', 'bProxyPath', 'bSkipBasicAuth', 'bLocalhostPasskeys', 'backupBeforeSave', 'backupPath', 'autoReload', 'atRelock', 'atRemember', 'trayStyle', 'quickShortcut', 'sshEnabled', 'sshAuthSock', 'ksImport', 'ksExport',
] as const;
const KNOWN_KEY = 'anotherkeepass.vaults';

// ponytail: localStorage (WebView storage); a Tauri store plugin is only needed if settings must be shared across profiles
// null = first run → setup wizard
function loadSettings(): Settings | null {
  try {
    const raw = JSON.parse(localStorage.getItem(SETTINGS_KEY) ?? 'null');
    // Ctrl+Alt+Space (old default) is often taken by other tools
    if (raw && raw.quickShortcut === 'Ctrl+Alt+Space') raw.quickShortcut = 'Ctrl+Alt+K';
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
    document.documentElement.dataset.accent = settings?.accent ?? 'terracotta';
    document.documentElement.lang = lang;
    document.documentElement.style.setProperty('--zoom', String(zoom));
  }, [theme, lang, zoom, settings?.accent]);

  useEffect(() => { openOptions.minimize = !!settings?.minimizeOnUrl; }, [settings?.minimizeOnUrl]);
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
          onKnown={(path, patch) => setKnown(list => {
            const next = 'forget' in patch ? list.filter(k => k.path !== path) : list.map(k => k.path === path ? { ...k, ...patch } : k);
            saveKnown(next); return next;
          })}
          onOpened={opened} onUpdate={onUpdate} onClosed={onClosed} onLock={lock} desktopProblems={desktopProblems} />}
    </ContextMenuProvider>
  );
}

function Vaults({ t, settings, onSettings, onKnown, open, known, onOpened, onUpdate, onClosed, onLock, desktopProblems }: {
  t: Strings; settings: Settings; onSettings: (s: Settings) => void;
  onKnown: (path: string, patch: Partial<Known>) => void;
  open: Record<string, VaultData>; known: Known[];
  onOpened: (d: VaultData, meta: Known) => void; onUpdate: (d: VaultData) => void; onClosed: (id: string) => void; onLock: () => void;
  desktopProblems: string[];
}) {
  const [vault, setVault] = useState(ALL);
  const [folder, setFolder] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  // multi-select (Ctrl/Shift+click) for bulk move / pin / trash
  // belongs to the vault/folder it was made in: switching scope clears it
  const [multiSel, setMultiSel] = useState<{ scope: string; ids: string[] }>({ scope: '', ids: [] });
  const scope = vault + '|' + folder;
  const multi = multiSel.scope === scope ? multiSel.ids : [];
  const setMulti = (ids: string[]) => setMultiSel({ scope, ids });
  const [selected, setSelected] = useState<string | null>(null);
  const [pending, setPending] = useState<Item | null>(null); // new entry, not saved yet
  const [newMenu, setNewMenu] = useState(false);
  const [showGen, setShowGen] = useState(false);
  const [importFor, setImportFor] = useState<string | null>(null);
  const [shareFor, setShareFor] = useState<Folder | null>(null);
  const [settingsFor, setSettingsFor] = useState<{ vault: string; upgrade?: boolean } | null>(null);
  const [lookFor, setLookFor] = useState<VaultInfo | null>(null);
  const [exportFor, setExportFor] = useState<VaultInfo | null>(null);
  const [mergeFor, setMergeFor] = useState<VaultInfo | null>(null);
  const [syncFor, setSyncFor] = useState<VaultInfo | null>(null);
  const [preview, setPreview] = useState<{ name: string; load: () => Promise<Uint8Array> } | null>(null);
  const [palette, setPalette] = useState(false);
  const [folderDialog, setFolderDialog] = useState<{ mode: 'create' | 'rename'; vault?: string; id?: string; name?: string; parent?: string } | null>(null);
  const openMenu = useContextMenu();
  const [vaultDialog, setVaultDialog] = useState<{ path?: string } | null>(null);
  const [keyDialog, setKeyDialog] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const [tag, setTag] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState<string | null>(null);
  const dragItem = useRef<Item | null>(null);
  const [showKeys, setShowKeys] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);
  const { notify, snackbar } = useSnack();
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
  const ts = settingsStrings[settings.lang];

  // clear search query after it sat untouched
  useEffect(() => {
    if (!settings.clearSearch || !query) return;
    const id = setTimeout(() => setQuery(''), settings.clearSearchMinutes * 60_000);
    return () => clearTimeout(id);
  }, [query, settings.clearSearch, settings.clearSearchMinutes]);

  const items = useMemo(() => Object.values(open).flatMap(v => v.items.map(r => rawToItemCached(r, v))), [open]);
  const allItems = useMemo(() => pending ? [...items, pending] : items, [items, pending]);
  const folders: Folder[] = useMemo(() => Object.values(open).flatMap(v =>
    v.folders.map(f => ({ id: f.id, vault: v.id, name: f.name, parent: f.parent, share: f.share }))), [open]);
  const { update, pick, setPick, ask, setAsk } = useDesktopEvents({ t, settings, notify, open, vault, items, desktopProblems, onLock });
  const vaultList: VaultInfo[] = useMemo(() => {
    const ids = [...known.map(k => k.path), ...Object.keys(open).filter(id => !known.some(k => k.path === id))];
    return ids.map(id => {
      const k = known.find(x => x.path === id);
      return { id, name: open[id]?.name ?? k?.name ?? fileName(id), file: fileName(id), color: k?.color ?? '--v-clay', icon: k?.icon ?? 'shield_lock', locked: !open[id] };
    });
  }, [known, open]);

  const chosen = multi.length > 1 ? allItems.filter(i => multi.includes(i.id)) : [];
  const { run, apply, copyText, copyField, requestTrash, restoreItem, deleteForever, emptyTrash, togglePin, moveItem, duplicate, loadIcons, removeIcon, historyRestore, download, bulkTrash, bulkMove, bulkPin } =
    useItemActions({ t, settings, notify, open, items, folders, vaultList, chosen, onUpdate, setSelected, setConfirm, setMulti });

  const { health, breaches, checking, issue, setIssue, issuesOf, issueName, issueLabel, checkBreaches, healthCounts } =
    useHealth({ t, active: vault === HEALTH, open, notify });
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
    return sortItems(list, settings.listSort as SortMode);
  }, [allItems, vault, folder, query, settings.listSort, tag, issue, issuesOf]);
  // tags present in the current vault/folder scope, for the filter chips
  const scopeTags = useMemo(() => [...new Set(allItems
    .filter(i => vault === TRASH ? i.trashed : !i.trashed && (vault === ALL || i.vault === vault) && (!folder || i.folder === folder))
    .flatMap(i => i.tags ?? []))].sort((a, b) => a.localeCompare(b)), [allItems, vault, folder]);

  const openIds = Object.keys(open);
  const targetVault = open[vault] ? vault : openIds[0];
  const createItem = (type: ItemType, preset?: Field[]) => {
    const item: Item = {
      id: 'new:' + crypto.randomUUID(), vault: targetVault, type, title: '', subtitle: '',
      folder: folder && folders.some(f => f.id === folder && f.vault === targetVault) ? folder : undefined,
      fields: (preset ?? TEMPLATES[type] ?? []).map(f => f.key === 'password' && settings.generateForNew
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
      ...(backend.desktop ? [
        { icon: 'ios_share', label: t.exportMenu, action: () => setExportFor(v) },
        ...(isRemote(v.id) ? [] : [{ icon: 'merge', label: t.mergeMenu, action: () => setMergeFor(v) }, { icon: 'sync_alt', label: t.syncMenu, action: () => setSyncFor(v) }]),
      ] : [{ icon: 'print', label: t.exportSheet, action: () => setExportFor(v) }]),
      ...(backend.desktop ? [{ icon: 'image_search', label: t.loadIcons, action: () => loadIcons(items.filter(i => i.vault === v.id && !i.trashed && !i.icon)) }] : []),
      ...(isRemote(v.id) ? [
        { icon: 'sync', label: t.vwSync, action: async () => { if (apply(await run(backend.vaultSync(v.id)))) notify(t.vwSynced); } },
        { icon: 'logout', label: t.vwSignOut, danger: true, action: () => setConfirm({ title: t.vwSignOut, body: t.vwSignOutBody, label: t.vwSignOut, icon: 'logout',
          action: async () => { await run(backend.bwSignOut(v.id)); onClosed(v.id); onKnown(v.id, { forget: true } as Partial<Known>); } }) },
      ] : [{ icon: 'tune', label: t.vaultSettings, action: () => setSettingsFor({ vault: v.id }) }]),
      { icon: 'palette', label: t.vaultLook, action: () => setLookFor(v) },
      ...(isRemote(v.id) ? [] : [{ icon: 'key', label: t.changeMasterKey, action: () => setKeyDialog(v.id) }]),
      'sep',
      { icon: 'lock', label: t.closeVault, action: () => closeVault(v.id) },
    ];

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

  const current = allItems.find(i => i.id === selected) ?? null;
  const grouped = useMemo(() => vault === HEALTH || settings.listGroup === 'none' ? null : groupItems(visible, settings.listGroup as GroupMode, {
    other: t.others, noFolder: t.noFolder, noWebsite: t.noWebsite, noTag: t.noTag,
    today: t.today, yesterday: t.yesterday, week: t.thisWeek, month: t.thisMonth, older: t.older,
    type: ty => t[ty], folder: id => folders.find(f => f.id === id)?.name ?? '—', vault: id => vaultList.find(v => v.id === id)?.name ?? '—',
  }), [visible, settings.listGroup, vault, folders, vaultList, t]);
  const order = grouped ? grouped.flatMap(g => g.items) : visible;
  // click: select; Ctrl/⌘+click: toggle in selection; Shift+click: range from the current entry
  const choose = (e: React.MouseEvent, id: string) => {
    if (e.ctrlKey || e.metaKey) {
      const base = multi.length ? multi : selected ? [selected] : [];
      setMulti(base.includes(id) ? base.filter(x => x !== id) : [...base, id]);
      return;
    }
    if (e.shiftKey && selected) {
      const ids = order.map(i => i.id);
      const [a, b] = [ids.indexOf(selected), ids.indexOf(id)].sort((x, y) => x - y);
      if (a >= 0 && b >= 0) { setMulti(ids.slice(a, b + 1)); return; }
    }
    setMulti([]);
    setSelected(id);
  };
  const row = (i: Item, group = '') => (
    <Row key={group + i.id} t={t} item={i} letters={settings.letterAvatars} active={multi.length > 1 ? multi.includes(i.id) : i.id === selected} onClick={e => choose(e, i.id)}
      dragRef={dragItem} onDragEnd={() => setDragOver(null)}
      onContextMenu={e => { if (!i.id.startsWith('new:')) { setSelected(i.id); openMenu(e, itemMenu(i)); } }} />
  );
  // Ctrl+K: actions first, then every entry of the open vaults
  const paletteItems: PaletteItem[] = useMemo(() => {
    const close = (fn: () => void) => () => { setPalette(false); fn(); };
    const actions: PaletteItem[] = [
      ...NEW_TYPES.map(ty => ({ id: 'new-' + ty, icon: TYPE_ICON[ty], label: `${t.actNew}: ${t[ty]}`, run: close(() => createItem(ty)) })),
      { id: 'gen', icon: 'password', label: t.actGenerator, run: close(() => setShowGen(true)) },
      { id: 'health', icon: 'health_and_safety', label: t.actHealth, run: close(() => selectVault(HEALTH)) },
      { id: 'trash', icon: 'delete', label: t.actTrash, run: close(() => selectVault(TRASH)) },
      { id: 'import', icon: 'upload_file', label: t.importItems, run: close(() => setImportFor(targetVault)) },
      { id: 'theme', icon: 'contrast', label: t.actTheme, run: close(() => onSettings({ ...settings, theme: settings.theme === 'dark' ? 'light' : 'dark' })) },
      { id: 'settings', icon: 'settings', label: t.actSettings, run: close(() => setPage('settings')) },
      { id: 'lock', icon: 'lock', label: t.actLock, run: close(onLock) },
    ];
    const entries: PaletteItem[] = allItems.filter(i => !i.trashed && !i.id.startsWith('new:')).map(i => ({
      id: 'e-' + i.vault + i.id, icon: TYPE_ICON[i.type], image: i.icon, label: i.title || t.untitled, sub: i.subtitle,
      hint: vaultList.length > 1 ? vaultList.find(v => v.id === i.vault)?.name : undefined,
      run: close(() => { setVault(ALL); setFolder(null); setMulti([]); setSelected(i.id); }),
      alt: close(() => { const f = i.fields.find(x => x.raw === 'Password'); if (f) copyField(i, f, t.password); }),
    }));
    return [...actions, ...entries];
  }, [allItems, vaultList, t, settings, targetVault]); // eslint-disable-line react-hooks/exhaustive-deps
  const pinned = visible.filter(i => i.pinned);
  const rest = visible.filter(i => !i.pinned);

  // keyboard shortcuts (KeePassXC-like); entry-level ones act on the selected entry
  const shortcutRef = useRef<(e: KeyboardEvent) => void>(() => {});
  const onShortcut = (e: KeyboardEvent) => {
    const typing = e.target instanceof Element && e.target.closest('input, textarea, select, [contenteditable=true]') !== null;
    const mod = e.ctrlKey || e.metaKey;
    const field = (raw: string) => current?.fields.find(f => f.raw === raw);
    const totpField = current?.fields.find(f => f.kind === 'totp');
    const run1 = (fn: () => void) => { e.preventDefault(); fn(); };
    if (e.key === 'F5' || (mod && ['r', 'p', 'j', 'h', 'g', 's', 'o'].includes(e.key.toLowerCase()))) { e.preventDefault(); return; }
    if (e.key === 'F1' || (mod && e.key === '/')) return run1(() => setShowKeys(s => !s));
    if (e.key === 'Escape') { window.dispatchEvent(new Event('akp:cancel')); setShowKeys(false); setMulti([]); return; }
    if (mod && e.key.toLowerCase() === 'k') return run1(() => setPalette(p => !p));
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
  // the listener stays registered once; it always calls the handler of the latest render
  useEffect(() => { shortcutRef.current = onShortcut; });
  useEffect(() => {
    const h = (e: KeyboardEvent) => shortcutRef.current(e);
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, []);
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
                <span className="menu-label">{t.templates}</span>
                {TEMPLATE_PRESETS.map(p => (
                  <button key={p.id} role="menuitem" onClick={() => createItem(p.type, p.fields(t))}>
                    <span className="avatar sm other"><Icon n={p.icon} /></span>{t[p.label]}
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
            {open[activeVault.id]?.remote === false && <span className="pill offline-pill" title={t.vwOfflineHint}><Icon n="cloud_off" />{t.offline}</span>}
            {open[activeVault.id]?.syncWith && (
              <span className="pill offline-pill" title={`${t.syncChip} ${fileName(open[activeVault.id].syncWith!)}`}><Icon n="sync_alt" />{fileName(open[activeVault.id].syncWith!).split(' · ')[0]}</span>
            )}
            {isRemote(activeVault.id)
              ? <button className="icon-btn" title={t.vwSync} aria-label={t.vwSync} onClick={async () => { if (apply(await run(backend.vaultSync(activeVault.id)))) notify(t.vwSynced); }}><Icon n="sync" /></button>
              : <>
                <button className="icon-btn" title={t.vaultSettings} aria-label={t.vaultSettings} onClick={() => setSettingsFor({ vault: activeVault.id })}><Icon n="tune" /></button>
                <button className="icon-btn" title={t.changeMasterKey} aria-label={t.changeMasterKey} onClick={() => setKeyDialog(activeVault.id)}><Icon n="key" /></button>
              </>}
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
          <span className="chip on count-chip">{t.all} · {visible.length}</span>
          <button className="chip" title={t.sortBy} onClick={e => openMenu(e, SORTS.map(([k, icon, label]) => ({
            icon: settings.listSort === k ? 'check' : icon, label: t[label], action: () => onSettings({ ...settings, listSort: k }) })))}>
            <Icon n="swap_vert" />{t[SORTS.find(s => s[0] === settings.listSort)?.[2] ?? 'sortTitle']}
          </button>
          <button className={'chip' + (settings.listGroup !== 'none' ? ' on' : '')} title={t.groupBy} onClick={e => openMenu(e, GROUPS.map(([k, icon, label]) => ({
            icon: settings.listGroup === k ? 'check' : icon, label: t[label], action: () => onSettings({ ...settings, listGroup: k }) })))}>
            <Icon n="segment" />{settings.listGroup === 'none' ? t.groupBy : t[GROUPS.find(g => g[0] === settings.listGroup)?.[2] ?? 'grNone']}
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
        <div className={'items' + (settings.listDensity === 'compact' ? ' compact' : '')} key={vault + '|' + (folder ?? '')}>
          {visible.length === 0 && <div className="empty"><Icon n={vault === HEALTH ? 'verified_user' : 'eco'} />{vault === HEALTH ? t.hOk : t.noItems}</div>}
          {grouped && grouped.map(g => (
            <div key={g.key} className="list-group" id={'grp-' + g.key}>
              <span className="label group-label">{g.label}<small>{g.items.length}</small></span>
              {g.items.map(i => row(i, g.key))}
            </div>
          ))}
          {!grouped && pinned.length > 0 && <span className="label group-label">{t.pinned}</span>}
          {!grouped && pinned.map(i => row(i))}
          {!grouped && rest.length > 0 && pinned.length > 0 && <span className="label group-label">{t.others}</span>}
          {vault === HEALTH && rest.map(i => <HealthRow key={i.id} t={t} item={i} issues={issuesOf(i.id)} label={k => issueLabel(k, i.id)}
            active={i.id === selected} onClick={() => setSelected(i.id)} />)}
          {vault !== HEALTH && !grouped && rest.map(i => row(i))}
        </div>
        {grouped && settings.listGroup === 'letter' && grouped.length > 3 && (
          <nav className="jump-bar" aria-label={t.grLetter}>
            {grouped.map(g => <button key={g.key} onClick={() => document.getElementById('grp-' + g.key)?.scrollIntoView({ block: 'start', behavior: 'smooth' })}>{g.label}</button>)}
          </nav>
        )}
      </section>

      <main className="pane detail">
        {chosen.length > 1 ? (
          <div className="bulk">
            <div className="bulk-head"><span className="bulk-count">{chosen.length}</span><b>{t.selected}</b></div>
            <p className="dialog-body">{t.selectionHint}</p>
            <label className="opt">{t.moveTo}
              <select className="set-select" value="" onChange={e => e.target.value && bulkMove(e.target.value)}>
                <option value="">—</option>
                {vaultList.filter(v => !v.locked).map(v => [
                  <option key={v.id} value={v.id + '|'}>{v.name}</option>,
                  ...folders.filter(f => f.vault === v.id).map(f => <option key={f.id} value={v.id + '|' + f.id}>{'\u00a0\u00a0' + f.name}</option>),
                ])}
              </select>
            </label>
            <div className="row">
              <button className="btn tonal" onClick={() => bulkPin(true)}><Icon n="push_pin" />{t.pinItem}</button>
              <button className="btn tonal" onClick={() => bulkPin(false)}><Icon n="keep_off" />{t.unpinItem}</button>
              <button className="btn tonal danger-tonal" onClick={bulkTrash}><Icon n="delete" />{ts.ui.moveToTrash}</button>
              <button className="btn text" onClick={() => setMulti([])}>{t.clearSelection}</button>
            </div>
          </div>
        ) : current ? (
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
            onPreview={a => setPreview({ name: a.name, load: async () => a.file ? new Uint8Array(await a.file.arrayBuffer())
              : Uint8Array.from(atob(await backend.attachmentGet(current.vault, current.id, a.name)), c => c.charCodeAt(0)) })}
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
      {palette && createPortal(
        <div className="scrim palette-scrim" onClick={() => setPalette(false)}>
          <div className="palette-dialog" role="dialog" aria-label={t.palette} onClick={e => e.stopPropagation()}>
            <CommandPalette items={paletteItems} placeholder={t.paletteSearch} onClose={() => setPalette(false)} empty={t.noItems}
              hints={[{ keys: '↵', label: t.paOpen, icon: 'open_in_full' }, { keys: 'Ctrl ↵', label: t.password, icon: 'key' }]} />
          </div>
        </div>, document.body)}
      {exportFor && <ExportDialog t={t} vault={exportFor} onClose={() => setExportFor(null)} onDone={notify} />}
      {syncFor && <SyncDialog t={t} vaultList={vaultList} syncWith={open[syncFor.id]?.syncWith}
        onLink={async remote => { const d = await run(backend.syncLink(syncFor.id, remote)); if (d) { onUpdate(d); notify(remote ? t.syncLinked : t.syncUnlinked); setSyncFor(null); } }}
        onClose={() => setSyncFor(null)} />}
      {mergeFor && <MergeDialog t={t} vault={mergeFor} onClose={() => setMergeFor(null)} onMerged={(d, msg) => { onUpdate(d); notify(msg); }} />}
      {preview && <AttachmentPreview t={t} name={preview.name} load={preview.load} onClose={() => setPreview(null)} />}
      {lookFor && (
        <VaultLookDialog t={t} vault={lookFor} onClose={() => setLookFor(null)}
          onSave={(color, icon) => { onKnown(lookFor.id, { color, icon }); setLookFor(null); }} />
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
      {confirm && <ConfirmDialog t={t} confirm={confirm} onClose={() => setConfirm(null)} />}
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

const SORTS: [SortMode, string, 'sortTitle' | 'sortTitleDesc' | 'sortModified' | 'sortCreated'][] = [
  ['title', 'sort_by_alpha', 'sortTitle'], ['titleDesc', 'sort_by_alpha', 'sortTitleDesc'], ['modified', 'history', 'sortModified'], ['created', 'new_releases', 'sortCreated'],
];
const GROUPS: [GroupMode, string, 'grNone' | 'grLetter' | 'grType' | 'grFolder' | 'grVault' | 'grDomain' | 'grTag' | 'grDate'][] = [
  ['none', 'view_list', 'grNone'], ['letter', 'abc', 'grLetter'], ['type', 'category', 'grType'], ['folder', 'folder', 'grFolder'],
  ['vault', 'stacks', 'grVault'], ['domain', 'language', 'grDomain'], ['tag', 'sell', 'grTag'], ['date', 'calendar_month', 'grDate'],
];
