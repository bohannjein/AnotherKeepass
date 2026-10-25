// Searchable list of entries and actions with keyboard control. Used for Ctrl+K in the main
// window and as the whole UI of the quick access window.
import { useEffect, useMemo, useRef, useState } from 'react';
import { Icon } from './Icon';

export interface PaletteItem {
  id: string;
  icon: string;
  /** image (website icon) instead of the symbol */
  image?: string;
  label: string;
  sub?: string;
  /** small text on the right, e.g. the vault */
  hint?: string;
  run: () => void;
  /** Ctrl+Enter */
  alt?: () => void;
  /** Shift+Enter */
  shift?: () => void;
}

const norm = (s: string) => s.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '');

/** Every search word must appear in label or sub; label matches rank first. */
function rank(items: PaletteItem[], q: string) {
  const words = norm(q).split(/\s+/).filter(Boolean);
  if (!words.length) return items;
  return items
    .map(it => {
      const label = norm(it.label), sub = norm(it.sub ?? '');
      if (!words.every(w => label.includes(w) || sub.includes(w))) return null;
      return { it, score: (label.startsWith(words[0]) ? 0 : label.includes(words[0]) ? 1 : 2) };
    })
    .filter((x): x is { it: PaletteItem; score: number } => !!x)
    .sort((a, b) => a.score - b.score)
    .map(x => x.it);
}

export interface PaletteHint { keys: string; label: string; icon: string }

export function CommandPalette({ items, placeholder, hints, empty, onClose, autoFocusKey }: {
  items: PaletteItem[]; placeholder: string; hints?: PaletteHint[]; empty: string; onClose: () => void; autoFocusKey?: unknown;
}) {
  const [q, setQ] = useState('');
  const [sel, setSel] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const shown = useMemo(() => rank(items, q).slice(0, 60), [items, q]);
  useEffect(() => { input.current?.focus(); }, [autoFocusKey]);
  useEffect(() => { list.current?.querySelector('.on')?.scrollIntoView({ block: 'nearest' }); }, [sel]);

  const key = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setSel(s => Math.min(shown.length - 1, s + 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setSel(s => Math.max(0, s - 1)); }
    else if (e.key === 'Escape') { e.preventDefault(); onClose(); }
    else if (e.key === 'Enter') {
      e.preventDefault();
      const it = shown[sel];
      if (!it) return;
      if ((e.ctrlKey || e.metaKey) && it.alt) it.alt();
      else if (e.shiftKey && it.shift) it.shift();
      else it.run();
    }
  };

  return (
    <div className="palette" onKeyDown={key}>
      <label className="palette-search">
        <span className="palette-logo"><Icon n="shield_lock" fill /></span>
        <input ref={input} autoFocus value={q} onChange={e => { setQ(e.target.value); setSel(0); }} placeholder={placeholder} aria-label={placeholder} spellCheck={false} />
      </label>
      <div className="palette-list" ref={list} role="listbox">
        {!shown.length && <div className="palette-empty"><span className="blob"><Icon n="search_off" /></span>{empty}</div>}
        {shown.map((it, i) => (
          <button key={it.id} role="option" aria-selected={i === sel} className={'palette-item' + (i === sel ? ' on' : '')}
            onMouseEnter={() => setSel(i)} onClick={e => (e.ctrlKey && it.alt ? it.alt() : it.run())}>
            {it.image ? <span className="avatar favicon"><img src={it.image} alt="" /></span> : <span className="avatar pal"><Icon n={it.icon} /></span>}
            <span className="palette-text"><b>{it.label}</b>{it.sub && <small>{it.sub}</small>}</span>
            {it.hint && <span className="palette-hint">{it.hint}</span>}
          </button>
        ))}
      </div>
      {hints && (
        <div className="palette-footer">
          {hints.map(h => <span key={h.keys} className="hint-chip"><Icon n={h.icon} /><b>{h.keys}</b>{h.label}</span>)}
        </div>
      )}
    </div>
  );
}
