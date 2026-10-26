// The quick access window (?quick=1): search all unlocked vaults, Enter copies the password,
// Shift+Enter the username, Ctrl+Enter types the login via Auto-Type, Esc or a click outside closes.
// The global Auto-Type opens it as picker: matching entries first, Enter types.
import { useCallback, useEffect, useMemo, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { backend, type AutoTypePick, type VaultData } from './backend';
import { CommandPalette, type PaletteItem } from './CommandPalette';
import { strings, type Lang } from './i18n';
import { sortItems } from './listGroups';
import { rawToItem } from './model';

const SETTINGS_KEY = 'anotherkeepass.settings';
const readSettings = () => {
  try { return JSON.parse(localStorage.getItem(SETTINGS_KEY) ?? '{}'); } catch { return {}; }
};
const hide = () => invoke('quick_hide');

export default function QuickApp() {
  const [vaults, setVaults] = useState<VaultData[]>([]);
  const [pick, setPick] = useState<AutoTypePick | null>(null);
  const settings = readSettings();
  const t = strings[(settings.lang ?? 'en') as Lang];
  const clearAfter = settings.clipboardClear === false ? null : settings.clipboardSeconds ?? 10;

  const reload = useCallback(() => {
    // same look as the main window
    document.documentElement.dataset.theme = readSettings().theme ?? 'dark';
    document.documentElement.dataset.accent = readSettings().accent ?? 'terracotta';
    backend.vaultsListing().then(setVaults).catch(() => setVaults([]));
    backend.quickPick().then(setPick).catch(() => setPick(null));
  }, []);
  useEffect(reload, [reload]);
  useEffect(() => backend.on('akp-locked', () => setVaults([])), []);

  // clicking another window closes us (Rust also does on focus loss, which WebView2 does not always report).
  // Armed a moment after opening: the focus settles first, an early blur would close the window at once.
  useEffect(() => {
    const arm = setTimeout(() => window.addEventListener('blur', hide), 400);
    // Esc anywhere in the window, not only in the search field; focus back into the field
    const esc = (e: KeyboardEvent) => { if (e.key === 'Escape') hide(); };
    const refocus = () => document.querySelector<HTMLInputElement>('.palette-search input')?.focus();
    window.addEventListener('keydown', esc);
    window.addEventListener('focus', refocus);
    return () => {
      clearTimeout(arm);
      window.removeEventListener('blur', hide);
      window.removeEventListener('keydown', esc);
      window.removeEventListener('focus', refocus);
    };
  }, []);

  const items: PaletteItem[] = useMemo(() => {
    const all = vaults.flatMap(v => v.items.filter(i => !i.trashed).map(raw => ({ it: rawToItem(raw, v), v })));
    const order = new Map(sortItems(all.map(x => x.it), 'used').map((it, n) => [it.vault + it.id, n]));
    // Auto-Type: the entries matching the window first, with their own sequence
    const seq = new Map(pick?.candidates.map((c, n) => [c.vault + c.id, [n, c.sequence] as const]));
    const rank = (key: string) => seq.get(key)?.[0] ?? seq.size + (order.get(key) ?? 0);
    return all.sort((a, b) => rank(a.v.id + a.it.id) - rank(b.v.id + b.it.id)).map(({ it, v }) => {
      const has = (name: string) => it.fields.some(f => f.raw === name && (f.value || f.protected));
      const copy = (field: string) => async () => {
        if (!has(field)) return;
        await backend.copy(v.id, it.id, field, false, clearAfter);
        hide();
      };
      const type = () => { hide(); backend.autotypePerform(v.id, it.id, seq.get(v.id + it.id)?.[1] ?? null); };
      return {
        id: v.id + it.id,
        icon: it.type === 'login' ? 'person' : it.type === 'card' ? 'credit_card' : 'key',
        image: it.icon,
        label: it.title || t.untitled,
        sub: it.subtitle,
        hint: vaults.length > 1 ? v.name : undefined,
        run: pick ? type : copy('Password'),
        shift: copy('UserName'),
        alt: pick ? copy('Password') : type,
      };
    });
  }, [vaults, pick, t, clearAfter]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    // the window is larger than the panel (shadow); a click on that margin counts as outside
    <div className="quick" onMouseDown={e => { if (e.target === e.currentTarget) hide(); }}>
      <CommandPalette items={items} onClose={hide} autoFocusKey={pick} empty={vaults.length ? t.noItems : t.quickLocked}
        placeholder={pick ? `${t.autoTypePick} ${pick.windowTitle || '…'}` : t.quickSearch}
        hints={pick ? [
          { keys: '↵', label: t.autoType, icon: 'keyboard' },
          { keys: '⇧ ↵', label: t.username, icon: 'person' },
          { keys: 'Ctrl ↵', label: t.password, icon: 'key' },
        ] : [
          { keys: '↵', label: t.password, icon: 'key' },
          { keys: '⇧ ↵', label: t.username, icon: 'person' },
          { keys: 'Ctrl ↵', label: t.autoType, icon: 'keyboard' },
        ]} />
    </div>
  );
}
