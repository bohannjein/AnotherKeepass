// Main window columns: menu | entry list | detail. The menu folds into an icon rail on narrow
// windows or on request; both borders can be dragged. Widths live in the settings, while
// dragging only in state.
import { useEffect, useRef, useState } from 'react';
import { DEFAULTS, clamp, type Prefs } from './settings';

const NARROW = '(max-width: 1199px)';
export const RAIL_W = 84, GAP = 12, MIN_DETAIL = 360;
type Live = { drawer?: number; list?: number };

/** [callback ref, whether the element's content is taller than the element (it scrolls)].
 *  A callback ref, so a re-mounted element (rail toggle) is observed again. */
export function useScrolls() {
  const [el, setEl] = useState<HTMLElement | null>(null);
  const [scrolls, setScrolls] = useState(false);
  useEffect(() => {
    if (!el) return;
    const check = () => setScrolls(el.scrollHeight > el.clientHeight + 1);
    const ro = new ResizeObserver(check);
    ro.observe(el);
    // content changes (vaults, folders) don't resize the box itself
    const mo = new MutationObserver(check);
    mo.observe(el, { childList: true, subtree: true });
    check();
    return () => { ro.disconnect(); mo.disconnect(); };
  }, [el]);
  return [setEl, scrolls] as const;
}

export function useColumns(settings: Prefs, onSettings: (s: Prefs) => void) {
  const [isNarrow, setIsNarrow] = useState(() => window.matchMedia(NARROW).matches);
  const [rail, setRail] = useState(isNarrow);
  useEffect(() => {
    const mq = window.matchMedia(NARROW);
    const onChange = () => { setIsNarrow(mq.matches); setRail(mq.matches); };
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);
  const [winW, setWinW] = useState(() => window.innerWidth);
  useEffect(() => {
    const h = () => setWinW(window.innerWidth);
    window.addEventListener('resize', h);
    return () => window.removeEventListener('resize', h);
  }, []);

  const [live, setLive] = useState<Live | null>(null);
  const zoom = settings.fontSize / 100;
  const drawerW = clamp(live?.drawer ?? settings.drawerWidth, 200, 420);
  const drawerCol = rail || isNarrow ? RAIL_W : drawerW;
  const listMax = Math.max(240, winW / zoom - GAP - drawerCol - 2 * GAP - MIN_DETAIL);
  const listW = clamp(Math.min(live?.list ?? settings.listWidth, listMax), 240, 720);

  // the ref is updated with the state so a key step can drag and commit in one go
  const liveRef = useRef(live);
  const put = (l: Live) => { liveRef.current = l; setLive(l); };
  const dragDrawer = (w: number) => {
    // pulling the drawer narrow folds it into the icon rail, pulling the rail out unfolds it
    if (rail) { if (w > 160) { setRail(false); put({ ...liveRef.current, drawer: Math.max(200, w) }); } return; }
    if (w < 140) { setRail(true); put({ ...liveRef.current, drawer: undefined }); return; }
    put({ ...liveRef.current, drawer: w });
  };
  const dragList = (w: number) => put({ ...liveRef.current, list: w });
  const endDrag = () => {
    const l = liveRef.current;
    liveRef.current = null;
    setLive(null);
    if (!l) return;
    const next = { ...settings };
    if (l.drawer !== undefined) next.drawerWidth = clamp(l.drawer, 200, 420);
    if (l.list !== undefined) next.listWidth = clamp(Math.min(l.list, listMax), 240, 720);
    if (next.drawerWidth !== settings.drawerWidth || next.listWidth !== settings.listWidth) onSettings(next);
  };
  const resetDrawer = () => { setRail(false); onSettings({ ...settings, drawerWidth: DEFAULTS.drawerWidth }); };
  const resetList = () => onSettings({ ...settings, listWidth: DEFAULTS.listWidth });

  return { isNarrow, rail, setRail, resizing: !!live, zoom, drawerCol, listW, dragDrawer, dragList, endDrag, resetDrawer, resetList };
}
