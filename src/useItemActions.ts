// What can be done with entries: copy (secrets go Rust → clipboard), trash/restore/delete,
// pin, move, duplicate, website icons, history, attachments, and the same for a multi-selection.
// Every backend call goes through run(): errors become a snackbar instead of an exception.
import { useEffect, useState } from 'react';
import { save as saveDialog } from '@tauri-apps/plugin-dialog';
import { backend, demoAttachment, type VaultData } from './backend';
import { draftToInput, type Attachment, type Draft, type Field, type Folder, type Item, type VaultInfo } from './model';
import { type Strings } from './i18n';
import { type Prefs } from './settings';
import { settingsStrings } from './i18n-settings';
import { toPng } from './ui';
import { type Notify } from './useSnack';

export type Confirm = { title: string; body: string; label: string; icon: string; action: () => void };

export function useItemActions({ t, settings, notify, open, items, folders, vaultList, chosen, onUpdate, setSelected, setConfirm, setMulti }: {
  t: Strings; settings: Prefs; notify: Notify; open: Record<string, VaultData>; items: Item[]; folders: Folder[]; vaultList: VaultInfo[];
  chosen: Item[]; onUpdate: (d: VaultData) => void; setSelected: (id: string | null) => void; setConfirm: (c: Confirm) => void;
  setMulti: (ids: string[]) => void;
}) {
  const ts = settingsStrings[settings.lang];
  const run = async <T,>(p: Promise<T>): Promise<T | undefined> => {
    try { return await p; } catch (e) {
      const m = String(e);
      notify(m.includes('remote_move_loses_data') ? t.errRemoteMove : `${t.saveError}: ${m}`, true);
      return undefined;
    }
  };
  const apply = (d: VaultData | undefined) => { if (d) onUpdate(d); return !!d; };

  const clearAfter = settings.clipboardClear ? settings.clipboardSeconds : null;
  const copied = (what: string) => {
    notify(`${what} ${t.copied}`);
    if (settings.onCopy !== 'none') backend.windowMinimize();
    setCopies(n => n + 1);
  };
  // "clipboard cleared" notice; a newer copy restarts the countdown
  const [copies, setCopies] = useState(0);
  useEffect(() => {
    if (!copies || !clearAfter) return;
    const id = setTimeout(() => notify(ts.ui.clipboardCleared), clearAfter * 1000);
    return () => clearTimeout(id);
  }, [copies]); // eslint-disable-line react-hooks/exhaustive-deps -- only a new copy starts the countdown
  const copyText = async (text: string, what: string) => {
    if ((await run(backend.copyText(text, clearAfter))) !== undefined || !backend.desktop) copied(what);
  };
  // stored fields are copied by the backend, so secrets never pass through the UI
  const copyField = async (item: Item, f: Field, what: string) => {
    if (item.id.startsWith('new:') || !f.raw) return copyText(f.value, what);
    try { await backend.copy(item.vault, item.id, f.raw, f.kind === 'totp', clearAfter); copied(what); }
    catch (e) { notify(`${t.saveError}: ${String(e)}`, true); }
  };

  const doTrash = async (item: Item) => {
    if (apply(await run(backend.trash(item.vault, item.id)))) {
      setSelected(null);
      notify(ts.ui.movedToTrash, false, { label: t.undo, run: async () => { if (apply(await run(backend.restore(item.vault, item.id)))) setSelected(item.id); } });
    }
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

  const duplicate = async (item: Item) => {
    const res = await run(backend.duplicate(item.vault, item.id, ` (${t.copySuffix})`));
    if (res) { onUpdate(res[1]); setSelected(res[0]); }
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

  const bulkTrash = async () => {
    const done: Item[] = [];
    for (const it of chosen) if (apply(await run(backend.trash(it.vault, it.id)))) done.push(it);
    setMulti([]); setSelected(null);
    notify(`${done.length} ${t.trashedN}`, false, { label: t.undo, run: async () => { for (const it of done) apply(await run(backend.restore(it.vault, it.id))); } });
  };
  const bulkMove = async (target: string) => {
    const [vid, fid] = target.split('|');
    let n = 0;
    for (const it of chosen) {
      const ok = it.vault === vid ? apply(await run(backend.move(it.vault, it.id, fid || null)))
        : !!(await run(backend.moveToVault(it.vault, it.id, vid, fid || null)).then(r => r && (onUpdate(r[0]), onUpdate(r[1]), true)));
      if (ok) n++;
    }
    setMulti([]);
    notify(`${n} ${t.movedN}`);
  };
  const bulkPin = async (pin: boolean) => {
    for (const it of chosen) if (!!it.pinned !== pin) await togglePin(it);
  };

  return { run, apply, copyText, copyField, doTrash, requestTrash, restoreItem, deleteForever, emptyTrash, togglePin, moveItem, duplicate, loadIcons, removeIcon, historyRestore, download, bulkTrash, bulkMove, bulkPin };
}
