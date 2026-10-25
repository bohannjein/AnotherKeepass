// Everything the main window reacts to without the user clicking: events from Rust (browser
// requests, Auto-Type, sync problems, reloads), the weekly update check, auto-lock after
// inactivity and one-time notices after unlocking.
import { useEffect, useRef, useState } from 'react';
import { backend, type AutoTypePick, type BrowserAsk, type Update, type VaultData } from './backend';
import { type Item } from './model';
import { type Strings } from './i18n';
import { type Prefs } from './settings';
import { type Notify } from './useSnack';

export function useDesktopEvents({ t, settings, notify, open, vault, items, desktopProblems, onLock }: {
  t: Strings; settings: Prefs; notify: Notify; open: Record<string, VaultData>; vault: string; items: Item[];
  desktopProblems: string[]; onLock: () => void;
}) {
  const [update, setUpdate] = useState<Update | null>(null);
  const [pick, setPick] = useState<AutoTypePick | null>(null);
  const [ask, setAsk] = useState<BrowserAsk | null>(null);

  useEffect(() => backend.on<BrowserAsk>('akp-browser-ask', a => setAsk(a)), []);
  useEffect(() => backend.on<string>('akp-sync-problem', e => notify(`${t.syncProblem}: ${e}`, true)), [t.syncProblem, notify]);
  useEffect(() => backend.on('akp-vault-reloaded', () => notify(t.vaultReloaded)), [t.vaultReloaded, notify]);

  // auto-type: picker request and errors come from Rust
  useEffect(() => {
    const a = backend.on<AutoTypePick>('akp-autotype-pick', p => setPick(p));
    const b = backend.on<string>('akp-autotype-error', e => notify(`${t.autoTypeError}: ${e}`, true));
    return () => { a(); b(); };
  }, [t.autoTypeError, notify]);

  // update check: at most once a week, only when enabled
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
  }, [settings.updateCheck, settings.updateBeta]); // eslint-disable-line react-hooks/exhaustive-deps -- once per setting change, not per language switch

  // auto-lock after inactivity
  useEffect(() => {
    if (!settings.autoLock) return;
    let id = setTimeout(onLock, settings.autoLockSeconds * 1000);
    const reset = () => { clearTimeout(id); id = setTimeout(onLock, settings.autoLockSeconds * 1000); };
    const events = ['pointermove', 'pointerdown', 'keydown', 'wheel'] as const;
    events.forEach(e => window.addEventListener(e, reset));
    return () => { clearTimeout(id); events.forEach(e => window.removeEventListener(e, reset)); };
  }, [settings.autoLock, settings.autoLockSeconds, onLock]);

  // KDBX 3.1 files: say once that saving upgrades them (a backup is written next to the file)
  const formatNoticed = useRef(new Set<string>());
  useEffect(() => {
    for (const v of Object.values(open)) {
      if (v.format.startsWith('KDBX 3') && !formatNoticed.current.has(v.id)) {
        formatNoticed.current.add(v.id);
        notify(`${v.name}: ${t.kdbx3Notice}`);
      }
    }
  }, [open, t.kdbx3Notice, notify]);

  useEffect(() => {
    // a taken shortcut gets a clear sentence instead of the raw error
    const text = desktopProblems.map(p => /^(quickShortcut|shortcut):.*already registered/.test(p)
      ? t.shortcutTaken.replace('{k}', p.startsWith('quick') ? settings.quickShortcut : settings.atShortcut) : p);
    if (text.length) notify(`${t.desktopProblem}: ${text.join(', ')}`, true);
  }, [desktopProblems, t.desktopProblem]); // eslint-disable-line react-hooks/exhaustive-deps -- only when new problems arrive, not when a shortcut is edited

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
  }, [items, settings.showExpiring, settings.expiryDays, t.expiringSoon, notify]);

  return { update, pick, setPick, ask, setAsk };
}
