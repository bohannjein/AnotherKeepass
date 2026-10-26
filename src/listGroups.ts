// Sorting and grouping of the entry list (pure functions, see listGroups.check.ts).
import type { Item } from './model.ts';

export type SortMode = 'used' | 'title' | 'titleDesc' | 'modified' | 'created';
export type GroupMode = 'none' | 'letter' | 'type' | 'folder' | 'vault' | 'domain' | 'tag' | 'date';
export interface Group { key: string; label: string; items: Item[] }

export interface GroupLabels {
  other: string; noFolder: string; noWebsite: string; noTag: string;
  today: string; yesterday: string; week: string; month: string; older: string;
  type: (t: Item['type']) => string; folder: (id: string) => string; vault: (id: string) => string;
}

/** key of catch-all groups (#, no tag, no website): always listed last */
const LAST = String.fromCharCode(0xffff);
const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true });

export function sortItems(items: Item[], mode: SortMode): Item[] {
  const byTitle = (a: Item, b: Item) => collator.compare(a.title, b.title);
  // never used: the last change counts (KeePass sets "last access" on save, too)
  const used = (i: Item) => i.used ?? i.modifiedAt ?? i.modified;
  const list = [...items];
  switch (mode) {
    case 'used': return list.sort((a, b) => used(b).localeCompare(used(a)) || byTitle(a, b));
    case 'titleDesc': return list.sort((a, b) => byTitle(b, a));
    case 'modified': return list.sort((a, b) => (b.modifiedAt ?? b.modified).localeCompare(a.modifiedAt ?? a.modified) || byTitle(a, b));
    case 'created': return list.sort((a, b) => (b.created ?? '').localeCompare(a.created ?? '') || byTitle(a, b));
    default: return list.sort(byTitle);
  }
}

/** First letter without accents (Ä → A); digits and symbols go to "#". */
export function letterOf(title: string): string {
  const c = title.trim().normalize('NFD').replace(/[̀-ͯ]/g, '').charAt(0).toUpperCase();
  return /[A-Z]/.test(c) ? c : '#';
}

export function hostOf(item: Item): string {
  const url = item.fields.find(f => f.raw === 'URL' || f.kind === 'url')?.value ?? '';
  if (!url) return '';
  try { return new URL(url.includes('://') ? url : 'https://' + url).hostname.replace(/^www\./, ''); } catch { return ''; }
}

function dateBucket(item: Item, now: Date, l: GroupLabels): [string, string] {
  const d = new Date(item.modifiedAt ?? item.modified);
  if (isNaN(d.getTime())) return ['5', l.older];
  const day = 86_400_000;
  const startToday = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const t = d.getTime();
  if (t >= startToday) return ['0', l.today];
  if (t >= startToday - day) return ['1', l.yesterday];
  if (t >= startToday - 6 * day) return ['2', l.week];
  if (t >= startToday - 30 * day) return ['3', l.month];
  return ['4', l.older];
}

/** Items (already sorted) → sections. Entries with several tags appear under each tag. */
export function groupItems(items: Item[], mode: GroupMode, l: GroupLabels, now = new Date()): Group[] {
  if (mode === 'none') return [{ key: '', label: '', items }];
  const groups = new Map<string, Group>();
  const add = (key: string, label: string, item: Item) => {
    const g = groups.get(key) ?? { key, label, items: [] };
    g.items.push(item);
    groups.set(key, g);
  };
  for (const it of items) {
    switch (mode) {
      case 'letter': { const c = letterOf(it.title); add(c === '#' ? LAST : c, c, it); break; }
      case 'type': add(it.type, l.type(it.type), it); break;
      case 'folder': add(it.folder ? l.folder(it.folder).toLowerCase() : '', it.folder ? l.folder(it.folder) : l.noFolder, it); break;
      case 'vault': add(l.vault(it.vault).toLowerCase(), l.vault(it.vault), it); break;
      case 'domain': { const h = hostOf(it); add(h || LAST, h || l.noWebsite, it); break; }
      case 'tag': {
        const tags = it.tags?.length ? it.tags : null;
        if (!tags) add(LAST, l.noTag, it);
        else for (const t of tags) add(t.toLowerCase(), t, it);
        break;
      }
      case 'date': { const [k, label] = dateBucket(it, now, l); add(k, label, it); break; }
    }
  }
  return [...groups.values()].sort((a, b) => Number(a.key === LAST) - Number(b.key === LAST) || collator.compare(a.key, b.key));
}
