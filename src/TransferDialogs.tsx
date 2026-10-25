// Export (CSV / encrypted copy / emergency sheet), merge another .kdbx, attachment preview.
import { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { open as openDialog, save as saveDialog } from '@tauri-apps/plugin-dialog';
import { backend, errorCode, type VaultData } from './backend';
import type { Strings } from './i18n';
import { Icon } from './Icon';
import type { VaultInfo } from './model';
import { IMAGE } from './ui';

const fileName = (p: string) => p.split(/[\\/]/).pop() ?? p;

export function ExportDialog({ t, vault, onClose, onDone }: {
  t: Strings; vault: VaultInfo; onClose: () => void; onDone: (msg: string, error?: boolean) => void;
}) {
  const [kind, setKind] = useState<'copy' | 'csv' | 'sheet'>('copy');
  const [understood, setUnderstood] = useState(false);
  const [sheet, setSheet] = useState(false);
  const base = vault.name.replace(/[\\/:*?"<>|]/g, '_') || 'vault';

  const go = async () => {
    try {
      if (kind === 'sheet') { setSheet(true); return; }
      if (kind === 'copy') {
        const dest = await saveDialog({ defaultPath: `${base} (copy).kdbx`, filters: [{ name: t.kdbxFilter, extensions: ['kdbx'] }] });
        if (!dest) return;
        await backend.vaultSaveCopy(vault.id, dest);
        onDone(t.exportCopyDone);
      } else {
        const dest = await saveDialog({ defaultPath: `${base}.csv`, filters: [{ name: 'CSV', extensions: ['csv'] }] });
        if (!dest) return;
        const n = await backend.vaultExportCsv(vault.id, dest);
        onDone(`${n} ${t.exportCsvDone}`);
      }
      onClose();
    } catch (e) { onDone(String(e), true); }
  };

  if (sheet) return <EmergencySheet t={t} vault={vault} onClose={onClose} />;
  return createPortal(
    <div className="scrim" onClick={onClose}>
      <div className="dialog share-dialog" role="dialog" aria-label={t.exportTitle} onClick={e => e.stopPropagation()}>
        <h3><Icon n="ios_share" />{t.exportTitle}</h3>
        <div className="share-modes">
          {([['copy', 'enhanced_encryption', t.exportCopy, t.exportCopyHint], ['csv', 'table', t.exportCsv, t.exportCsvHint], ['sheet', 'print', t.exportSheet, t.exportSheetHint]] as const).map(([k, icon, label, hint]) => (
            <button key={k} type="button" className={'choice' + (kind === k ? ' on' : '')} onClick={() => setKind(k)}>
              <Icon n={icon} /><span><b>{label}</b><small>{hint}</small></span>
            </button>
          ))}
        </div>
        {kind === 'csv' && (
          <label className="opt warn-opt"><span><Icon n="warning" /> {t.exportCsvWarn}</span>
            <input className="switch" type="checkbox" checked={understood} onChange={e => setUnderstood(e.target.checked)} />
          </label>
        )}
        <div className="row">
          <button className="btn text" onClick={onClose}>{t.cancel}</button>
          <button className="btn filled" disabled={kind === 'csv' && !understood} onClick={go}><Icon n="check" />{kind === 'sheet' ? t.exportPrint : t.exportGo}</button>
        </div>
      </div>
    </div>, document.body);
}

/** Printable emergency kit: where the vault is and room to write the master password by hand. */
function EmergencySheet({ t, vault, onClose }: { t: Strings; vault: VaultInfo; onClose: () => void }) {
  const [created] = useState(() => new Date().toLocaleDateString()); // date printed on the sheet
  useEffect(() => {
    const done = () => onClose();
    window.addEventListener('afterprint', done);
    const id = setTimeout(() => window.print(), 300);
    return () => { clearTimeout(id); window.removeEventListener('afterprint', done); };
  }, [onClose]);
  return createPortal(
    <div className="print-sheet">
      <h1>AnotherKeepass – {t.sheetTitle}</h1>
      <p>{t.sheetIntro}</p>
      <table>
        <tbody>
          <tr><th>{t.vault}</th><td>{vault.name}</td></tr>
          <tr><th>{t.file}</th><td>{vault.id}</td></tr>
          <tr><th>{t.sheetCreated}</th><td>{created}</td></tr>
          <tr><th>{t.masterPassword}</th><td className="write-here" /></tr>
          <tr><th>{t.keyfile}</th><td className="write-here" /></tr>
          <tr><th>{t.sheetNotes}</th><td className="write-here tall" /></tr>
        </tbody>
      </table>
      <p className="small">{t.sheetKeep}</p>
      <button className="no-print btn filled" onClick={onClose}>{t.close}</button>
    </div>, document.body);
}

export function MergeDialog({ t, vault, onClose, onMerged }: {
  t: Strings; vault: VaultInfo; onClose: () => void; onMerged: (d: VaultData, msg: string) => void;
}) {
  const [path, setPath] = useState('');
  const [password, setPassword] = useState('');
  const [keyfile, setKeyfile] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const pick = async () => {
    const p = await openDialog({ multiple: false, directory: false, filters: [{ name: t.kdbxFilter, extensions: ['kdbx'] }] });
    if (typeof p === 'string') setPath(p);
  };
  const go = async () => {
    setBusy(true); setError('');
    try {
      const [s, d] = await backend.vaultMerge(vault.id, path, password, keyfile || undefined);
      onMerged(d, t.mergeDone.replace('{c}', String(s.created)).replace('{u}', String(s.updated)));
      onClose();
    } catch (e) {
      setError(errorCode(e) === 'wrong_key' ? t.wrongKey : String(e));
    }
    setBusy(false);
  };
  return createPortal(
    <div className="scrim" onClick={onClose}>
      <form className="dialog share-dialog" role="dialog" aria-label={t.mergeTitle} onClick={e => e.stopPropagation()} onSubmit={e => { e.preventDefault(); if (path) go(); }}>
        <h3><Icon n="merge" />{t.mergeTitle}</h3>
        <p className="dialog-body">{t.mergeBody.replace('{v}', vault.name)}</p>
        <button type="button" className="btn tonal path-btn" onClick={pick} title={path}><Icon n="description" /><span>{path ? fileName(path) : t.mergePick}</span></button>
        <label className="textfield"><Icon n="key" />
          <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder={t.masterPassword} aria-label={t.masterPassword} />
        </label>
        <button type="button" className="btn text" onClick={async () => { const p = await openDialog({ multiple: false }); if (typeof p === 'string') setKeyfile(p); }}>
          <Icon n="key_vertical" />{keyfile ? fileName(keyfile) : t.keyfile}
        </button>
        {error && <p className="form-error" role="alert"><Icon n="error" />{error}</p>}
        <div className="row">
          <button type="button" className="btn text" onClick={onClose}>{t.cancel}</button>
          <button type="submit" className="btn filled" disabled={busy || !path}><Icon n="merge" />{t.mergeGo}</button>
        </div>
      </form>
    </div>, document.body);
}


export function AttachmentPreview({ t, name, load, onClose }: { t: Strings; name: string; load: () => Promise<Uint8Array>; onClose: () => void }) {
  const [url, setUrl] = useState<string | null>(null);
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState('');
  useEffect(() => {
    let objectUrl = '';
    load().then(bytes => {
      if (IMAGE.test(name)) {
        const type = name.toLowerCase().endsWith('.svg') ? 'image/svg+xml' : '';
        objectUrl = URL.createObjectURL(new Blob([bytes.slice()], type ? { type } : {}));
        setUrl(objectUrl);
      } else setText(new TextDecoder().decode(bytes.slice(0, 512 * 1024)));
    }).catch(e => setError(errorCode(e) === 'too_large' ? t.previewTooLarge : String(e)));
    return () => { if (objectUrl) URL.revokeObjectURL(objectUrl); };
  }, [name, load, t.previewTooLarge]);
  return createPortal(
    <div className="scrim" onClick={onClose}>
      <div className="dialog preview-dialog" role="dialog" aria-label={name} onClick={e => e.stopPropagation()}>
        <h3><Icon n="visibility" /><span className="ellipsis">{name}</span></h3>
        {url && <img src={url} alt={name} />}
        {text !== null && <pre>{text}</pre>}
        {error && <p className="form-error"><Icon n="error" />{error}</p>}
        <div className="row"><button className="btn filled" onClick={onClose}>{t.close}</button></div>
      </div>
    </div>, document.body);
}
