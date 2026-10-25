// Entry list rows and side navigation items.
import { type Item } from './model';
import { type Strings } from './i18n';
import { Icon } from './Icon';
import { TYPE_ICON, isExpired } from './ui';

export function NavItem(p: {
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

/** Type avatar, or the entry's website/custom icon on a soft tile. */
const LETTER_COLORS = ['clay', 'moss', 'ochre', 'plum', 'sea', 'sand'];
/** Type avatar, website/custom icon, or (logins) a colored initial derived from the title. */
export function ItemAvatar({ item, letters = true }: { item: Item; letters?: boolean }) {
  if (item.icon) return <span className="avatar favicon"><img src={item.icon} alt="" draggable={false} /></span>;
  const initial = item.title.trim().charAt(0).toUpperCase();
  if (letters && item.type === 'login' && /\p{L}|\d/u.test(initial)) {
    let h = 0;
    for (const c of item.title.toLowerCase()) h = (h * 31 + c.charCodeAt(0)) >>> 0;
    return <span className={'avatar letter ' + LETTER_COLORS[h % LETTER_COLORS.length]}>{initial}</span>;
  }
  return <span className={'avatar ' + item.type}><Icon n={TYPE_ICON[item.type]} /></span>;
}

export function Row({ t, item, active, onClick, dragRef, onDragEnd, onContextMenu, letters }: {
  t: Strings; item: Item; active: boolean; onClick: (e: React.MouseEvent) => void; letters?: boolean;
  dragRef: React.MutableRefObject<Item | null>; onDragEnd: () => void; onContextMenu: (e: React.MouseEvent) => void;
}) {
  const saved = !item.id.startsWith('new:');
  return (
    <button className={'item' + (active ? ' active' : '')} onClick={onClick} onContextMenu={onContextMenu} draggable={saved}
      onDragStart={e => { dragRef.current = item; e.dataTransfer.effectAllowed = 'move'; e.dataTransfer.setData('text/plain', item.title); }}
      onDragEnd={() => { dragRef.current = null; onDragEnd(); }}>
      <ItemAvatar item={item} letters={letters} />
      <span><b>{item.title || t.untitled}</b><span>{item.subtitle || t[item.type]}</span></span>
      {isExpired(item) ? <span className="pin expired" title={t.expired}><Icon n="event_busy" /></span>
        : item.pinned && <span className="pin"><Icon n="push_pin" fill /></span>}
    </button>
  );
}
