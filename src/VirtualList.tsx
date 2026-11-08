// Entry list that only draws the rows in view once it gets long. Rows are group headers or
// entries; both kinds have one fixed height each (measured from a drawn row), so the position of
// every row is a sum and the hidden ones become two spacers.
import { useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode, type RefObject } from 'react';

export type VRow<T> = { key: string; head: ReactNode } | { key: string; id: string; item: T };
export type VirtualApi = { scrollToKey: (key: string) => void };

/** below this, every row is drawn (keeps the entry animation, costs nothing) */
const THRESHOLD = 300;
/** px drawn above and below the visible part */
const OVERSCAN = 800;

export function VirtualList<T>({ className, rows, render, selected, apiRef, children }: {
  className: string; rows: VRow<T>[]; render: (item: T, key: string) => ReactNode;
  /** id of the selected entry: kept in view when it changes (arrow keys, palette) */
  selected?: string | null; apiRef?: RefObject<VirtualApi | null>; children?: ReactNode;
}) {
  const box = useRef<HTMLDivElement>(null);
  const [view, setView] = useState({ top: 0, height: 1000 });
  const [size, setSize] = useState({ item: 66, head: 38 });
  const virtual = rows.length > THRESHOLD;

  const offsets = useMemo(() => {
    const o = new Float64Array(rows.length + 1);
    for (let i = 0; i < rows.length; i++) o[i + 1] = o[i] + ('head' in rows[i] ? size.head : size.item);
    return o;
  }, [rows, size]);

  // real row heights (density, font size); getBoundingClientRect includes the app zoom, so it is
  // divided out with the box's own ratio. Runs after every render (rows appear, density
  // changes); it only sets state when a height really differs, so it settles at once.
  // eslint-disable-next-line react-hooks/exhaustive-deps -- intentionally after every render
  useLayoutEffect(() => {
    const el = box.current;
    if (!el || !el.offsetHeight) return;
    const area = el.getBoundingClientRect();
    const ratio = area.height / el.offsetHeight || 1;
    // a row in view: rows off screen may still be unrendered placeholders (content-visibility)
    const pick = (sel: string) => {
      const all = el.querySelectorAll(sel);
      for (const e of all) { const r = e.getBoundingClientRect(); if (r.bottom > area.top && r.top < area.bottom) return e; }
      return all[0] ?? null;
    };
    const outer = (e: Element | null, fallback: number) => {
      if (!e) return fallback;
      const cs = getComputedStyle(e);
      return e.getBoundingClientRect().height / ratio + parseFloat(cs.marginTop) + parseFloat(cs.marginBottom);
    };
    const next = { item: outer(pick(':scope > .item'), size.item), head: outer(pick(':scope > .group-label'), size.head) };
    if (Math.abs(next.item - size.item) > 0.01 || Math.abs(next.head - size.head) > 0.01) setSize(next);
  });

  // follow scrolling and resizing (one update per frame)
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    let frame = 0;
    const read = () => { frame = 0; setView({ top: el.scrollTop, height: el.clientHeight }); };
    const onScroll = () => { if (!frame) frame = requestAnimationFrame(read); };
    read();
    el.addEventListener('scroll', onScroll, { passive: true });
    const ro = new ResizeObserver(onScroll);
    ro.observe(el);
    return () => { el.removeEventListener('scroll', onScroll); ro.disconnect(); cancelAnimationFrame(frame); };
  }, []);

  const indexOf = (key: string) => rows.findIndex(r => r.key === key);
  useEffect(() => {
    if (!apiRef) return;
    apiRef.current = {
      scrollToKey: key => {
        const i = indexOf(key);
        if (i >= 0) box.current?.scrollTo({ top: offsets[i], behavior: 'smooth' });
      },
    };
  });

  // keep the selected entry in view when the selection changes (not when the list changes)
  useEffect(() => {
    const el = box.current;
    if (!el || !selected) return;
    const i = rows.findIndex(r => 'id' in r && r.id === selected);
    if (i < 0) return;
    const head = i > 0 && 'head' in rows[i - 1] ? size.head : 0;
    if (offsets[i] - head < el.scrollTop) el.scrollTop = offsets[i] - head;
    else if (offsets[i + 1] > el.scrollTop + el.clientHeight) el.scrollTop = offsets[i + 1] - el.clientHeight + 12;
  }, [selected]); // eslint-disable-line react-hooks/exhaustive-deps -- only on a new selection

  let start = 0, end = rows.length;
  if (virtual) {
    const find = (y: number) => { // first row whose bottom is below y
      let lo = 0, hi = rows.length;
      while (lo < hi) { const mid = (lo + hi) >> 1; if (offsets[mid + 1] <= y) lo = mid + 1; else hi = mid; }
      return lo;
    };
    start = find(view.top - OVERSCAN);
    end = Math.min(rows.length, find(view.top + view.height + OVERSCAN) + 1);
  }

  return (
    <div ref={box} className={className + (virtual ? ' virtual' : '')}>
      {children}
      {virtual && <div aria-hidden style={{ height: offsets[start] }} />}
      {rows.slice(start, end).map(r => 'head' in r
        ? <span key={r.key} className="label group-label">{r.head}</span>
        : render(r.item, r.key))}
      {virtual && <div aria-hidden style={{ height: offsets[rows.length] - offsets[end] }} />}
    </div>
  );
}
