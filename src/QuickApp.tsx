// The quick access window (?quick=1): search all unlocked vaults, Enter copies the password,
// Shift+Enter the username, Ctrl+Enter types the login via Auto-Type, Esc closes.
import { useCallback, useEffect, useMemo, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { backend, type VaultData } from './backend';
import { CommandPalette, type PaletteItem } from './CommandPalette';
import { strings, type Lang } from './i18n';
import { rawToItem } from './model';

const SETTINGS_KEY = 'anotherkeepass.settings';
const readSettings = () => {
  try { return JSON.parse(localStorage.getItem(SETTINGS_KEY) ?? '{}'); } catch { return {}; }
};

export default function QuickApp() {
  const [vaults, setVaults] = useState<VaultData[]>([]);
  const settings = readSettings();
  const t = strings[(settings.lang ?? 'en') as Lang];
  const clearAfter = settings.clipboardClear === false ? null : settings.clipboardSeconds ?? 10;

  const reload = useCallback(() => {
    // same look as the main window
    document.documentElement.dataset.theme = readSettings().theme ?? 'dark';
    document.documentElement.dataset.accent = readSettings().accent ?? 'terracotta';
    backend.vaultsListing().then(setVaults).catch(() => setVaults([]));
  }, []);
  useEffect(reload, [reload]);
  useEffect(() => backend.on('akp-locked', () => setVaults([])), []);

  const hide = () => invoke('quick_hide');
  const items: PaletteItem[] = useMemo(() => vaults.flatMap(v => v.items.filter(i => !i.trashed).map(raw => {
    const it = rawToItem(raw, v);
    const has = (name: string) => it.fields.some(f => f.raw === name && (f.value || f.protected));
    const copy = (field: string) => async () => {
      if (!has(field)) return;
      await backend.copy(v.id, it.id, field, false, clearAfter);
      hide();
    };
    return {
      id: v.id + it.id,
      icon: it.type === 'login' ? 'person' : it.type === 'card' ? 'credit_card' : 'key',
      image: it.icon,
      label: it.title || t.untitled,
      sub: it.subtitle,
      hint: vaults.length > 1 ? v.name : undefined,
      run: copy('Password'),
      shift: copy('UserName'),
      alt: () => { hide(); backend.autotypePerform(v.id, it.id, null); },
    };
  })), [vaults, t, clearAfter]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="quick">
      <CommandPalette items={items} placeholder={t.quickSearch} onClose={hide} autoFocusKey={0} empty={vaults.length ? t.noItems : t.quickLocked}
        hints={[
          { keys: '↵', label: t.password, icon: 'key' },
          { keys: '⇧ ↵', label: t.username, icon: 'person' },
          { keys: 'Ctrl ↵', label: t.autoType, icon: 'keyboard' },
        ]} />
    </div>
  );
}
