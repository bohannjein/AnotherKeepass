// App-styled context menu replacing the WebView's default one.
// Components call `useContextMenu()(event, items)`; text fields get cut/copy/paste automatically.
import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { backend } from './backend';
import type { Strings } from './i18n';
import { Icon } from './Icon';

export type MenuItem =
  | { icon: string; label: string; action: () => void; kbd?: string; danger?: boolean; disabled?: boolean }
  | 'sep';

type Open = (e: React.MouseEvent | MouseEvent, items: MenuItem[]) => void;
const MenuCtx = createContext<Open>(() => {});
export const useContextMenu = () => useContext(MenuCtx);

const editable = (el: EventTarget | null): el is HTMLInputElement | HTMLTextAreaElement =>
  (el instanceof HTMLInputElement && !['checkbox', 'radio', 'range', 'file', 'button', 'submit', 'date'].includes(el.type))
  || el instanceof HTMLTextAreaElement;

/** Insert text at the caret the way typing would, so React's onChange sees it. */
function insertText(el: HTMLInputElement | HTMLTextAreaElement, text: string) {
  const start = el.selectionStart ?? el.value.length, end = el.selectionEnd ?? el.value.length;
  const next = el.value.slice(0, start) + text + el.value.slice(end);
  const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), 'value')!.set!;
  setter.call(el, next);
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.setSelectionRange(start + text.length, start + text.length);
}

export function ContextMenuProvider({ t, children }: { t: Strings; children: React.ReactNode }) {
  const [menu, setMenu] = useState<{ x: number; y: number; items: MenuItem[] } | null>(null);
  const close = useCallback(() => setMenu(null), []);

  const open: Open = useCallback((e, items) => {
    e.preventDefault();
    e.stopPropagation();
    if (items.some(i => i !== 'sep')) setMenu({ x: e.clientX, y: e.clientY, items });
  }, []);

  // everything not handled by a component: text fields get an edit menu, the rest none at all
  useEffect(() => {
    const onContext = (e: MouseEvent) => {
      if (e.defaultPrevented) return;
      e.preventDefault();
      const el = e.target;
      if (!editable(el)) { setMenu(null); return; }
      el.focus();
      const hasSel = (el.selectionEnd ?? 0) > (el.selectionStart ?? 0);
      const secret = el instanceof HTMLInputElement && el.type === 'password';
      setMenu({
        x: e.clientX, y: e.clientY, items: [
          { icon: 'content_cut', label: t.cut, kbd: 'Ctrl+X', disabled: !hasSel || secret || el.readOnly, action: () => document.execCommand('cut') },
          { icon: 'content_copy', label: t.copy, kbd: 'Ctrl+C', disabled: !hasSel || secret, action: () => document.execCommand('copy') },
          {
            icon: 'content_paste', label: t.paste, kbd: 'Ctrl+V', disabled: el.readOnly, action: async () => {
              const text = await backend.readText().catch(() => '');
              if (text) { el.focus(); insertText(el, text); }
            },
          },
          'sep',
          { icon: 'select_all', label: t.selectAll, kbd: 'Ctrl+A', action: () => { el.focus(); el.select(); } },
        ],
      });
    };
    document.addEventListener('contextmenu', onContext);
    return () => document.removeEventListener('contextmenu', onContext);
  }, [t]);

  return (
    <MenuCtx.Provider value={open}>
      {children}
      {menu && <Menu {...menu} onClose={close} />}
    </MenuCtx.Provider>
  );
}

function Menu({ x, y, items, onClose }: { x: number; y: number; items: MenuItem[]; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState({ left: x, top: y, origin: 'top left' });

  // keep inside the window: flip left/up when there's no room
  useLayoutEffect(() => {
    // offset* ignores the scale-in animation, getBoundingClientRect would measure the shrunken menu
    const w = ref.current!.offsetWidth, h = ref.current!.offsetHeight;
    const flipX = x + w > innerWidth - 8, flipY = y + h > innerHeight - 8;
    setPos({
      left: Math.max(8, flipX ? x - w : x),
      top: Math.max(8, flipY ? y - h : y),
      origin: `${flipY ? 'bottom' : 'top'} ${flipX ? 'right' : 'left'}`,
    });
    ref.current!.querySelector<HTMLButtonElement>('button:not(:disabled)')?.focus();
  }, [x, y]);

  useEffect(() => {
    const away = (e: Event) => { if (!ref.current?.contains(e.target as Node)) onClose(); };
    window.addEventListener('pointerdown', away, true);
    window.addEventListener('blur', onClose);
    window.addEventListener('resize', onClose);
    document.addEventListener('scroll', onClose, true);
    return () => {
      window.removeEventListener('pointerdown', away, true);
      window.removeEventListener('blur', onClose);
      window.removeEventListener('resize', onClose);
      document.removeEventListener('scroll', onClose, true);
    };
  }, [onClose]);

  const onKey = (e: React.KeyboardEvent) => {
    const buttons = [...ref.current!.querySelectorAll<HTMLButtonElement>('button:not(:disabled)')];
    const i = buttons.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); onClose(); }
    else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      e.stopPropagation();
      buttons[(i + (e.key === 'ArrowDown' ? 1 : -1) + buttons.length) % buttons.length]?.focus();
    } else if (e.key === 'Tab') e.preventDefault();
  };

  return createPortal(
    <div ref={ref} className="menu context-menu" role="menu" onKeyDown={onKey} onContextMenu={e => e.preventDefault()}
      style={{ left: pos.left, top: pos.top, transformOrigin: pos.origin }}>
      {items.map((it, i) => it === 'sep' ? <hr key={i} /> : (
        <button key={i} role="menuitem" disabled={it.disabled} className={it.danger ? 'danger' : undefined}
          onClick={() => { onClose(); it.action(); }}>
          <Icon n={it.icon} />{it.label}{it.kbd && <kbd>{it.kbd}</kbd>}
        </button>
      ))}
    </div>, document.body);
}
