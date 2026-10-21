// Vault (database) settings: name, description, recycle bin, history size, key derivation.
// `upgrade` preselects today's recommended KDF (Argon2id, 64 MiB, ~1 s) for weak old files.
import { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { backend, type VaultData, type VaultSettings } from './backend';
import type { Strings } from './i18n';
import { Icon } from './Icon';

export function VaultSettingsDialog({ t, vault, upgrade, onClose, onSaved }: {
  t: Strings; vault: string; upgrade?: boolean; onClose: () => void; onSaved: (d: VaultData) => void;
}) {
  const [s, setS] = useState<VaultSettings | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const set = (p: Partial<VaultSettings>) => setS(x => x && { ...x, ...p });

  const benchmark = async (base: VaultSettings) => {
    setBusy(true);
    try {
      const iterations = await backend.kdfBenchmark(base.memoryMib || 64, base.parallelism || 2, 1000);
      setS({ ...base, iterations });
    } catch (e) { setError(String(e)); }
    setBusy(false);
  };
  useEffect(() => {
    backend.vaultSettings(vault).then(cur => {
      if (upgrade) benchmark({ ...cur, kdf: 'argon2id', memoryMib: 64, parallelism: 2 });
      else setS(cur);
    }).catch(e => setError(String(e)));
  }, [vault, upgrade]); // eslint-disable-line react-hooks/exhaustive-deps

  const save = async () => {
    if (!s) return;
    setBusy(true); setError('');
    try { onSaved(await backend.vaultSettingsSet(vault, s)); onClose(); }
    catch (e) { setError(String(e)); }
    setBusy(false);
  };
  const argon = s?.kdf !== 'aes';

  return createPortal(
    <div className="scrim" onClick={onClose}>
      <div className="dialog vault-settings" role="dialog" aria-label={t.vaultSettings} onClick={e => e.stopPropagation()}>
        <h3><Icon n="tune" />{t.vaultSettings}</h3>
        {!s && !error && <p className="dialog-body">{t.vsMeasuring}</p>}
        {s && (
          <>
            <label className="textfield"><Icon n="badge" />
              <input value={s.name} onChange={e => set({ name: e.target.value })} placeholder={t.vsName} aria-label={t.vsName} />
            </label>
            <label className="textfield"><Icon n="notes" />
              <input value={s.description} onChange={e => set({ description: e.target.value })} placeholder={t.vsDescription} aria-label={t.vsDescription} />
            </label>
            <label className="opt">{t.vsRecycleBin}<input className="switch" type="checkbox" checked={s.recycleBin} onChange={e => set({ recycleBin: e.target.checked })} /></label>
            <label className="opt">{t.vsHistory}
              <span className="set-number"><input type="number" min={0} max={1000} value={s.historyMax} onChange={e => set({ historyMax: Number(e.target.value) })} /></span>
            </label>

            <span className="label">{t.vsEncryption}</span>
            {s.weak && <p className="form-note warn"><Icon n="warning" />{t.vsWeak}</p>}
            <label className="opt">{t.vsKdf}
              <select className="set-select" value={s.kdf} onChange={e => set({ kdf: e.target.value as VaultSettings['kdf'], ...(e.target.value === 'aes' ? { iterations: Math.max(s.iterations, 2_000_000) } : { memoryMib: s.memoryMib || 64, parallelism: s.parallelism || 2, iterations: s.kdf === 'aes' ? 10 : s.iterations }) })}>
                <option value="argon2id">Argon2id ({t.vsRecommended})</option>
                <option value="argon2d">Argon2d</option>
                <option value="aes">AES-KDF</option>
              </select>
            </label>
            {argon && (
              <>
                <label className="opt">{t.vsMemory}
                  <span className="set-number"><input type="number" min={1} max={4096} value={s.memoryMib} onChange={e => set({ memoryMib: Number(e.target.value) })} />MiB</span>
                </label>
                <label className="opt">{t.vsThreads}
                  <span className="set-number"><input type="number" min={1} max={64} value={s.parallelism} onChange={e => set({ parallelism: Number(e.target.value) })} /></span>
                </label>
              </>
            )}
            <label className="opt">{argon ? t.vsIterations : t.vsRounds}
              <span className="set-number"><input type="number" min={1} value={s.iterations} onChange={e => set({ iterations: Number(e.target.value) })} /></span>
            </label>
            {argon && (
              <button type="button" className="btn text" disabled={busy} onClick={() => benchmark(s)}>
                <Icon n="speed" />{t.vsBenchmark}
              </button>
            )}
            <p className="form-note"><Icon n="info" />{t.vsNote}</p>
          </>
        )}
        {error && <p className="form-error" role="alert"><Icon n="error" />{error}</p>}
        <div className="row">
          <button className="btn text" onClick={onClose}>{t.cancel}</button>
          <button className="btn filled" disabled={!s || busy} onClick={save}><Icon n="check" />{t.save}</button>
        </div>
      </div>
    </div>, document.body);
}
