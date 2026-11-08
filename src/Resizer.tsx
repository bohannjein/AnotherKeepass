// Drag handle between two layout columns (pointer + arrow keys, double-click resets).
import { useRef } from 'react';

type Props = {
  label: string;
  /** left edge in CSS px inside the (zoomed) .app grid */
  left: number;
  /** current width of the column left of the handle */
  value: number;
  zoom: number;
  onDrag: (width: number) => void;
  onEnd: () => void;
  onReset: () => void;
};

export function Resizer({ label, left, value, zoom, onDrag, onEnd, onReset }: Props) {
  const start = useRef<{ x: number; w: number } | null>(null);
  return (
    <div
      className="resizer"
      role="separator"
      aria-orientation="vertical"
      aria-label={label}
      aria-valuenow={Math.round(value)}
      title={label}
      tabIndex={0}
      style={{ left }}
      onPointerDown={e => {
        if (e.button !== 0) return;
        e.preventDefault();
        e.currentTarget.setPointerCapture(e.pointerId);
        start.current = { x: e.clientX, w: value };
      }}
      // the grid lives inside CSS zoom: pointer deltas are screen px, widths are CSS px
      onPointerMove={e => { if (start.current) onDrag(start.current.w + (e.clientX - start.current.x) / zoom); }}
      onPointerUp={e => {
        if (!start.current) return;
        start.current = null;
        e.currentTarget.releasePointerCapture(e.pointerId);
        onEnd();
      }}
      onLostPointerCapture={() => { if (start.current) { start.current = null; onEnd(); } }}
      onDoubleClick={onReset}
      onKeyDown={e => {
        if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
        e.preventDefault();
        onDrag(value + (e.key === 'ArrowLeft' ? -16 : 16));
        onEnd();
      }}
    />
  );
}
