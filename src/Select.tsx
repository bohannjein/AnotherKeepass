import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Icon } from './Icon';

export interface SelectOption { value: string; label: string; icon?: string; /** shown a step in (folders below a vault) */ indent?: boolean }

/**
 * A dropdown in the app's own look. The browser's <select> opens the system list, which does not
 * match the rest of the window (and cannot be styled in every WebView2 version).
 *   variant 'field'  → like a text field (forms and dialogs)
 *   variant 'pill'   → tonal pill (settings)
 *   variant 'inline' → no frame, takes the look of its surroundings (badge, text field)
 */
export function Select({ value, options, onChange, ariaLabel, variant = 'field', className = '', disabled = false, placeholder = '—', title }: {
  value: string; options: SelectOption[]; onChange: (v: string) => void; ariaLabel?: string;
  variant?: 'field' | 'pill' | 'inline'; className?: string; disabled?: boolean; placeholder?: string; title?: string;
}) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [box, setBox] = useState<{ left: number; top?: number; bottom?: number; width: number; max: number } | null>(null);
  const btn = useRef<HTMLButtonElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const typed = useRef({ text: '', at: 0 });
  const id = useId();
  const current = options.find(o => o.value === value);

  const show = () => {
    if (disabled) return;
    setActive(Math.max(0, options.findIndex(o => o.value === value)));
    setOpen(true);
  };
  const close = () => { setOpen(false); btn.current?.focus({ preventScroll: true }); };
  const pick = (o: SelectOption) => { setOpen(false); btn.current?.focus({ preventScroll: true }); if (o.value !== value) onChange(o.value); };

  // below the button, or above it when there is not enough room; as wide as the button at least
  useLayoutEffect(() => {
    if (!open || !btn.current) return;
    const r = btn.current.getBoundingClientRect();
    const below = innerHeight - r.bottom - 12, above = r.top - 12;
    const up = below < 180 && above > below;
    setBox({ left: Math.max(8, Math.min(r.left, innerWidth - Math.max(r.width, 200) - 8)), width: Math.max(r.width, 200),
      ...(up ? { bottom: innerHeight - r.top + 4 } : { top: r.bottom + 4 }), max: Math.max(120, Math.min(up ? above : below, 340)) });
  }, [open]);
  // follow the page when it scrolls or resizes: simplest is to close
  useEffect(() => {
    if (!open) return;
    const off = () => setOpen(false);
    window.addEventListener('resize', off);
    return () => window.removeEventListener('resize', off);
  }, [open]);
  useEffect(() => { if (open) list.current?.querySelector('[data-active=true]')?.scrollIntoView({ block: 'nearest' }); }, [open, active]);

  const onKey = (e: React.KeyboardEvent) => {
    if (disabled) return;
    if (!open) {
      if (['ArrowDown', 'ArrowUp', 'Enter', ' '].includes(e.key)) { e.preventDefault(); show(); }
      return;
    }
    const n = options.length;
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); setActive(a => (a + 1) % n); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive(a => (a - 1 + n) % n); }
    else if (e.key === 'Home') { e.preventDefault(); setActive(0); }
    else if (e.key === 'End') { e.preventDefault(); setActive(n - 1); }
    else if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.stopPropagation(); if (options[active]) pick(options[active]); }
    else if (e.key === 'Tab') setOpen(false);
    else if (e.key.length === 1 && !e.ctrlKey && !e.metaKey) {
      // typing jumps to the next option that starts with what was typed
      const now = Date.now();
      typed.current = { text: (now - typed.current.at < 700 ? typed.current.text : '') + e.key.toLowerCase(), at: now };
      const from = typed.current.text.length > 1 ? active : active + 1;
      for (let k = 0; k < n; k++) {
        const i = (from + k) % n;
        if (options[i].label.trim().toLowerCase().startsWith(typed.current.text)) { setActive(i); break; }
      }
    }
  };

  return (
    <>
      <button ref={btn} type="button" className={`select select-${variant} ${className}`.trim()} disabled={disabled} title={title}
        aria-label={ariaLabel} aria-haspopup="listbox" aria-expanded={open} aria-controls={open ? id : undefined}
        aria-activedescendant={open ? `${id}-${active}` : undefined}
        onClick={() => (open ? close() : show())} onKeyDown={onKey} onBlur={() => { /* the scrim handles outside clicks */ }}>
        {current?.icon && variant !== 'inline' && <Icon n={current.icon} />}
        <span className="select-text">{current?.label ?? placeholder}</span>
        <Icon n={open ? 'expand_less' : 'expand_more'} />
      </button>
      {open && box && createPortal(
        <>
          <div className="select-scrim" onClick={close} />
          <div ref={list} id={id} role="listbox" className="select-pop" data-popup-open aria-label={ariaLabel}
            style={{ left: box.left, minWidth: box.width, maxHeight: box.max, ...(box.top !== undefined ? { top: box.top } : { bottom: box.bottom }) }}>
            {options.map((o, i) => (
              <div key={o.value + i} id={`${id}-${i}`} role="option" aria-selected={o.value === value} data-active={i === active}
                className={'select-opt' + (o.value === value ? ' on' : '') + (i === active ? ' active' : '') + (o.indent ? ' indent' : '')}
                onMouseEnter={() => setActive(i)} onMouseDown={e => e.preventDefault()} onClick={() => pick(o)}>
                {o.icon && <Icon n={o.icon} />}<span>{o.label}</span>{o.value === value && <Icon n="check" />}
              </div>
            ))}
          </div>
        </>,
        document.body,
      )}
    </>
  );
}
