// KeeShare for one folder: mode, container file, share password.
import { useEffect, useState } from 'react';
import { open as openDialog, save as saveDialog } from '@tauri-apps/plugin-dialog';
import { backend, errorCode, type Share, type VaultData } from './backend';
import type { Strings } from './i18n';
import { Icon } from './Icon';

const MODES = ['sync', 'export', 'import'] as const;

export function ShareDialog({ t, vault, folder, name, onClose, onSaved }: {
  t: Strings; vault: string; folder: string; name: string; onClose: () => void; onSaved: (d: VaultData, msg: string) => void;
}) {
  const [cur, setCur] = useState<Share | null | undefined>(undefined);
  const [kind, setKind] = useState<Share['kind']>('sync');
  const [path, setPath] = useState('');
  const [password, setPassword] = useState('');
  const [show, setShow] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    backend.keeshareGet(vault, folder).then(s => {
      setCur(s);
      if (s) { setKind(s.kind); setPath(s.path); setPassword(s.password); }
    }).catch(() => setCur(null));
  }, [vault, folder]);

  const pick = async () => {
    const p = kind === 'import'
      ? await openDialog({ multiple: false, directory: false, filters: [{ name: t.kdbxFilter, extensions: ['kdbx'] }] })
      : await saveDialog({ defaultPath: name + '.kdbx', filters: [{ name: t.kdbxFilter, extensions: ['kdbx'] }] });
    if (typeof p === 'string') setPath(p.endsWith('.kdbx') ? p : p + '.kdbx');
  };
  const save = async (share: Share | null) => {
    setBusy(true); setError('');
    try {
      onSaved(await backend.keeshareSet(vault, folder, share), share ? t.shareSaved : t.shareRemoved);
      onClose();
    } catch (e) {
      const c = errorCode(e);
      setError(c === 'open' ? t.shareWrongPw : c === 'io' ? t.shareNoFile : String(e));
    } finally { setBusy(false); }
  };
  if (cur === undefined) return null;

  return (
    <div className="scrim" onClick={onClose}>
      <form className="dialog share-dialog" role="dialog" aria-label={t.shareTitle} onClick={e => e.stopPropagation()}
        onSubmit={e => { e.preventDefault(); if (path && password) save({ kind, path, password }); }}>
        <h3><Icon n="folder_shared" />{t.shareTitle}</h3>
        <p className="dialog-body">{t.shareBody}</p>
        <div className="share-modes">
          {MODES.map(m => (
            <button type="button" key={m} className={'choice' + (kind === m ? ' on' : '')} onClick={() => setKind(m)}>
              <Icon n={{ sync: 'sync', export: 'upload', import: 'download' }[m]} />
              <span><b>{{ sync: t.shareSync, export: t.shareExport, import: t.shareImport }[m]}</b>
                <small>{{ sync: t.shareSyncHint, export: t.shareExportHint, import: t.shareImportHint }[m]}</small></span>
            </button>
          ))}
        </div>
        <button type="button" className="btn tonal path-btn" onClick={pick} title={path}>
          <Icon n="description" /><span>{path ? path.split(/[\\/]/).pop() : t.shareFile}</span>
        </button>
        <label className="textfield">
          <Icon n="key" />
          <input type={show ? 'text' : 'password'} value={password} onChange={e => setPassword(e.target.value)} placeholder={t.sharePassword} aria-label={t.sharePassword} autoComplete="new-password" />
          <button type="button" className="icon-btn" onClick={() => setShow(s => !s)} aria-label={show ? t.hide : t.show}><Icon n={show ? 'visibility_off' : 'visibility'} /></button>
        </label>
        {error && <p className="form-error" role="alert"><Icon n="error" />{error}</p>}
        <div className="row">
          {cur && <button type="button" className="btn text danger" disabled={busy} onClick={() => save(null)}>{t.shareStop}</button>}
          <span style={{ flex: 1 }} />
          <button type="button" className="btn text" onClick={onClose}>{t.cancel}</button>
          <button type="submit" className="btn filled" disabled={busy || !path || !password}><Icon n="check" />{t.save}</button>
        </div>
      </form>
    </div>
  );
}
