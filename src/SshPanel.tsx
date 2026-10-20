// SSH agent card in the entry view (KeeAgent settings, stored as the KeeAgent.settings attachment
// so KeePassXC and KeeAgent read the same configuration).
import { useEffect, useState } from 'react';
import { backend, errorCode, type KeeAgent, type VaultData } from './backend';
import type { Strings } from './i18n';
import { Icon } from './Icon';

const SETTINGS = 'KeeAgent.settings';

export function SshPanel({ t, vault, id, files, onChanged, onMessage }: {
  t: Strings; vault: string; id: string; files: string[];
  onChanged: (d: VaultData) => void; onMessage: (msg: string, error?: boolean) => void;
}) {
  const [s, setS] = useState<KeeAgent | null | undefined>(undefined);
  const keys = files.filter(f => f !== SETTINGS);
  useEffect(() => { backend.sshSettings(vault, id).then(setS).catch(() => setS(null)); }, [vault, id, files.length]);
  if (s === undefined || !keys.length) return null;

  const save = async (next: KeeAgent | null) => {
    try { onChanged(await backend.sshSettingsSet(vault, id, next)); setS(next); }
    catch (e) { onMessage(String(e), true); }
  };
  const explain = (e: unknown) => {
    const c = errorCode(e);
    return c === 'ssh_agent' ? t.sshErrAgent : c === 'ssh_passphrase' ? t.sshErrPass : String(e);
  };
  const act = async (add: boolean) => {
    try {
      await (add ? backend.sshAdd(vault, id) : backend.sshRemove(vault, id));
      onMessage(add ? t.sshAdded : t.sshRemoved);
    } catch (e) { onMessage(explain(e), true); }
  };
  const set = (p: Partial<KeeAgent>) => s && save({ ...s, ...p });

  return (
    <div className="attach section ssh">
      <div className="attach-head">
        <Icon n="terminal" />
        <div><b>{t.sshAgent}</b></div>
        <input className="switch" type="checkbox" aria-label={t.sshUse} title={t.sshUse} checked={!!s?.allow}
          onChange={e => save(e.target.checked
            ? { ...(s ?? { addAtOpen: true, removeAtClose: true, confirm: false, lifetime: 0, attachment: keys[0] }), allow: true }
            : s && { ...s, allow: false })} />
      </div>
      {s?.allow && (
        <>
          <label className="opt">{t.sshKey}
            <select className="set-select" value={s.attachment} onChange={e => set({ attachment: e.target.value })}>
              {!keys.includes(s.attachment) && <option value={s.attachment}>—</option>}
              {keys.map(k => <option key={k} value={k}>{k}</option>)}
            </select>
          </label>
          <label className="opt">{t.sshAddOpen}<input className="switch" type="checkbox" checked={s.addAtOpen} onChange={e => set({ addAtOpen: e.target.checked })} /></label>
          <label className="opt">{t.sshRemoveLock}<input className="switch" type="checkbox" checked={s.removeAtClose} onChange={e => set({ removeAtClose: e.target.checked })} /></label>
          <label className="opt">{t.sshConfirm}<input className="switch" type="checkbox" checked={s.confirm} onChange={e => set({ confirm: e.target.checked })} /></label>
          <div className="row">
            <button className="btn text" onClick={() => act(false)}><Icon n="remove_circle" />{t.sshRemoveNow}</button>
            <button className="btn tonal" onClick={() => act(true)}><Icon n="add_circle" />{t.sshAddNow}</button>
          </div>
        </>
      )}
    </div>
  );
}
