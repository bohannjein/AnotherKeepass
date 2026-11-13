import { useEffect } from 'react';

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** The dialog on top: the last `.scrim` that holds a dialog. */
const topDialog = (): { scrim: HTMLElement; dialog: HTMLElement } | null => {
  const scrims = [...document.querySelectorAll<HTMLElement>('.scrim')].reverse();
  for (const scrim of scrims) {
    const dialog = scrim.querySelector<HTMLElement>('[role=dialog], [role=alertdialog]');
    if (dialog) return { scrim, dialog };
  }
  return null;
};

/**
 * Keyboard and screen reader basics that every dialog shares, in one place instead of in each:
 * Escape closes the dialog on top (and nothing behind it reacts), Tab stays inside it, focus
 * returns to where it was, dialogs and switches announce themselves as such.
 */
export function useDialogA11y() {
  useEffect(() => {
    const mark = (root: ParentNode) => {
      root.querySelectorAll<HTMLElement>('[role=dialog], [role=alertdialog]').forEach(d => d.setAttribute('aria-modal', 'true'));
      root.querySelectorAll<HTMLInputElement>('input.switch').forEach(i => i.setAttribute('role', 'switch'));
    };
    mark(document);

    // remember the opener of each dialog, give focus back when it is gone
    const openers = new Map<HTMLElement, Element | null>();
    const obs = new MutationObserver(records => {
      for (const r of records) {
        r.addedNodes.forEach(n => {
          if (!(n instanceof HTMLElement)) return;
          mark(n);
          if (n.classList.contains('scrim') && !openers.has(n)) {
            openers.set(n, document.activeElement);
            // a dialog without an autofocus field still gets focus, so Tab and Escape work
            queueMicrotask(() => {
              const d = n.querySelector<HTMLElement>('[role=dialog], [role=alertdialog]');
              if (d && !d.contains(document.activeElement)) (d.querySelector<HTMLElement>(FOCUSABLE) ?? d).focus({ preventScroll: true });
            });
          }
        });
        r.removedNodes.forEach(n => {
          if (!(n instanceof HTMLElement)) return;
          const scrims = n.classList.contains('scrim') ? [n] : [...n.querySelectorAll<HTMLElement>('.scrim')];
          for (const s of scrims) {
            const opener = openers.get(s);
            openers.delete(s);
            if (opener instanceof HTMLElement && opener.isConnected && (!document.activeElement || document.activeElement === document.body)) {
              opener.focus({ preventScroll: true });
            }
          }
        });
      }
    });
    obs.observe(document.body, { childList: true, subtree: true });

    const onKey = (e: KeyboardEvent) => {
      const top = topDialog();
      if (!top) return;
      if (e.key === 'Escape') {
        // a dialog that handles Escape itself (the browser access question) says so
        // an open dropdown list closes first (it handles the key itself, see Select.tsx)
        if (document.querySelector('[data-popup-open]')) return;
        if (top.scrim.querySelector('[data-own-escape]') || e.defaultPrevented) return;
        e.preventDefault();
        e.stopPropagation(); // the edit form behind a dialog must not react to the same key
        top.scrim.click();
      } else if (e.key === 'Tab') {
        const items = [...top.dialog.querySelectorAll<HTMLElement>(FOCUSABLE)].filter(el => el.offsetParent !== null);
        if (!items.length) { e.preventDefault(); return; }
        const first = items[0], last = items[items.length - 1];
        const at = document.activeElement;
        if (!top.dialog.contains(at)) { e.preventDefault(); first.focus(); }
        else if (e.shiftKey && at === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && at === last) { e.preventDefault(); first.focus(); }
      }
    };
    window.addEventListener('keydown', onKey, true);
    return () => { obs.disconnect(); window.removeEventListener('keydown', onKey, true); };
  }, []);
}
