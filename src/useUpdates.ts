// Updates like on a phone: check at start and once a day, download in the background; Rust
// installs on its own while the app is unused in the tray (updateAuto). Lives at the top of the
// app so it also runs while every vault is locked, which is exactly when the app sits in the tray.
import { useCallback, useEffect, useRef, useState } from 'react';
import { backend, type Update } from './backend';
import { type Prefs } from './settings';

const UPDATE_KEY = 'anotherkeepass.updateChecked';
export type UpdateState = Update & { ready?: boolean; progress?: number };

export function useUpdates(settings: Prefs | null) {
  const [update, setUpdate] = useState<UpdateState | null>(null);
  useEffect(() => backend.on<number>('akp-update-progress', p => setUpdate(u => u && { ...u, progress: p })), []);

  const beta = settings?.updateBeta ?? false;
  const auto = settings?.updateAuto ?? false;
  const notice = settings?.updateNotify ?? false;
  const checking = useRef(false);
  /** manual: also download when automatic updates are off (the user asked) */
  const checkUpdate = useCallback(async (manual: boolean): Promise<UpdateState | null> => {
    if (!backend.desktop || checking.current) return null;
    checking.current = true;
    try {
      const u = await backend.updateCheck(beta);
      try { localStorage.setItem(UPDATE_KEY, String(Date.now())); } catch { /* no storage */ }
      if (!u) { setUpdate(null); return null; }
      setUpdate(old => old?.version === u.version ? old : u);
      if (!u.installable || !(auto || manual)) return u;
      const ready = await backend.updateDownload(auto);
      if (!ready) return u;
      const done = { ...u, ready: true };
      setUpdate(done);
      return done;
    } finally {
      checking.current = false;
    }
  }, [beta, auto]);

  const checkRef = useRef(checkUpdate);
  useEffect(() => { checkRef.current = checkUpdate; }, [checkUpdate]);
  useEffect(() => {
    if (!backend.desktop || !(auto || notice)) return;
    const due = () => {
      let last = 0;
      try { last = Number(localStorage.getItem(UPDATE_KEY) ?? 0); } catch { /* no storage */ }
      if (Date.now() - last > 20 * 3_600_000) checkRef.current(false).catch(e => backend.log('warn', 'update check: ' + String(e)));
    };
    const first = setTimeout(due, 5_000);
    const hourly = setInterval(due, 3_600_000);
    return () => { clearTimeout(first); clearInterval(hourly); };
  }, [auto, notice, beta]);

  return { update, checkUpdate };
}
