// Snackbar at the bottom of the main window: short notices, errors, and an optional action (undo).
import { useCallback, useEffect, useState } from 'react';
import { Icon } from './Icon';

export type SnackAction = { label: string; run: () => void };
export type Notify = (msg: string, error?: boolean, action?: SnackAction | null) => void;

export function useSnack() {
  const [snack, setSnack] = useState<{ msg: string; error: boolean; action: SnackAction | null } | null>(null);
  // stable identity, so effects can list it as a dependency
  const notify: Notify = useCallback((msg, error = false, action = null) => setSnack({ msg, error, action }), []);

  useEffect(() => {
    if (!snack) return;
    // errors and undo stay longer; longer text stays longer
    const id = setTimeout(() => setSnack(null), snack.error || snack.action ? 6000 : Math.max(2000, snack.msg.length * 60));
    return () => clearTimeout(id);
  }, [snack]);

  const snackbar = snack && (
    <div className={'snackbar' + (snack.error ? ' error' : '')} role="status">
      <Icon n={snack.error ? 'error' : 'check_circle'} />{snack.msg}
      {snack.action && <button className="snack-action" onClick={() => { snack.action?.run(); setSnack(null); }}>{snack.action.label}</button>}
    </div>
  );
  return { notify, snackbar };
}
