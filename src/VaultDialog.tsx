// Open / create / unlock a vault. Used as the lock screen and as the "add vault" dialog.
// Server accounts (Bitwarden/Vaultwarden) are shown disabled as a reminder: not built yet.
import { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { open as openDialog, save as saveDialog } from '@tauri-apps/plugin-dialog';
import { backend, errorCode, type VaultData } from './backend';
import type { Strings } from './i18n';
import { Icon } from './Icon';

export interface Known { path: string; name: string; color: string; icon: string; keyfile?: string }

const COLORS = ['--v-clay', '--v-moss', '--v-ochre'];
const ICONS = ['shield_lock', 'cottage', 'apartment', 'work_history', 'savings', 'school'];
export const fileName = (path: string) => path.replace(/^demo:/, '').split(/[\\/]/).pop() ?? path;

type Mode = 'open' | 'create';

export default function VaultDialog({ t, known, missing = [], onMissing, initialPath, initialMode = 'open', modal, onOpened, onClose }: {
  t: Strings; known: Known[]; missing?: string[]; onMissing?: (path: string) => void;
  initialPath?: string; initialMode?: Mode; modal?: boolean;
  onOpened: (data: VaultData, meta: Known) => void; onClose?: () => void;
}) {
  const [mode, setMode] = useState<Mode>(initialMode);
  const [path, setPath] = useState(initialPath ?? known[0]?.path ?? '');
  const [extraPath, setExtraPath] = useState<string | null>(null); // file picked that isn't remembered yet
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [keyfile, setKeyfile] = useState('');
  // remembered key file of the selected vault (only stored when "remember key files" is on)
  useEffect(() => { setKeyfile(known.find(k => k.path === path)?.keyfile ?? ''); }, [path, known]);
  // quick unlock offered when this vault was locked (not closed) with the option on
  const [quick, setQuick] = useState(false);
  useEffect(() => {
    let live = true;
    setQuick(false);
    if (mode === 'open' && path && backend.desktop) backend.quickAvailable(path).then(ok => { if (live) setQuick(ok); }).catch(() => {});
    return () => { live = false; };
  }, [mode, path]);
  const hello = async () => {
    setError(''); setBusy(true);
    try {
      const data = await backend.quickUnlock(path, t.helloPrompt);
      onOpened(data, { ...meta(path, data.name), name: data.name, keyfile: keyfile || undefined });
    } catch (err) {
      setError(errorCode(err) === 'hello_cancel' ? t.helloFailed : explain(err));
    } finally { setBusy(false); }
  };
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const meta = (p: string, n: string): Known => known.find(k => k.path === p)
    ?? { path: p, name: n, color: COLORS[known.length % COLORS.length], icon: ICONS[known.length % ICONS.length] };

  const pickFile = async () => {
    const p = await openDialog({ multiple: false, directory: false, filters: [{ name: t.kdbxFilter, extensions: ['kdbx'] }] });
    if (typeof p === 'string') { setExtraPath(p); setPath(p); setError(''); }
  };
  const pickKeyfile = async () => {
    const p = await openDialog({ multiple: false, directory: false });
    if (typeof p === 'string') setKeyfile(p);
  };
  const pickLocation = async () => {
    const p = await saveDialog({ defaultPath: (name.trim() || 'Passwords') + '.kdbx', filters: [{ name: t.kdbxFilter, extensions: ['kdbx'] }] });
    if (p) setPath(p.endsWith('.kdbx') ? p : p + '.kdbx');
  };

  const explain = (e: unknown) => {
    const code = errorCode(e);
    return code === 'wrong_key' ? t.wrongKey : code === 'empty_key' ? t.masterPassword : `${t.fileError} (${String(e)})`;
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (mode === 'create' && password !== confirm) { setError(t.passwordsDontMatch); return; }
    const target = mode === 'create' && !backend.desktop ? `demo:${(name.trim() || 'vault').toLowerCase()}.kdbx` : path;
    if (!target) return;
    setBusy(true);
    try {
      const data = mode === 'open'
        ? await backend.open(target, password, keyfile || undefined)
        : await backend.create(target, name.trim() || fileName(target).replace(/\.kdbx$/, ''), password, keyfile || undefined);
      setPassword(''); setConfirm('');
      onOpened(data, { ...meta(target, data.name), name: data.name, keyfile: keyfile || undefined });
    } catch (err) {
      // file gone since last time: drop it from the remembered list
      if (mode === 'open' && errorCode(err) === 'io' && /os error [23]/.test(String(err))) {
        onMissing?.(target);
        setPath('');
      }
      setError(explain(err));
    } finally {
      setBusy(false);
    }
  };

  const choices = [...known.map(k => k.path), ...(extraPath && !known.some(k => k.path === extraPath) ? [extraPath] : [])];
  const pwField = (value: string, set: (v: string) => void, label: string, autoFocus = false) => (
    <label className="textfield">
      <Icon n="key" />
      <input type={show ? 'text' : 'password'} placeholder={label} aria-label={label} value={value} autoFocus={autoFocus}
        onChange={e => set(e.target.value)} autoComplete="off" />
      <button type="button" className="icon-btn" onClick={() => setShow(s => !s)} aria-label={show ? t.hide : t.show}>
        <Icon n={show ? 'visibility_off' : 'visibility'} />
      </button>
    </label>
  );

  const body = (
    <form className={modal ? 'dialog vault-dialog' : 'sheet vault-dialog'} onSubmit={submit} onClick={e => e.stopPropagation()}
      role={modal ? 'dialog' : undefined} aria-label={mode === 'open' ? t.unlockVault : t.createVault}>
      {!modal && <div className="logo"><Icon n="lock" fill /></div>}
      {!modal && <h1>Another<span>Keepass</span></h1>}
      {modal && <h3><Icon n="add_moderator" />{t.addVault}</h3>}
      {!modal && <p>{known.length ? t.kdbxCompat : t.welcomeVaults}</p>}
      {missing.length > 0 && <p className="form-note" role="status"><Icon n="info" />{t.missingFiles} {missing.join(', ')}</p>}

      <div className="seg vault-modes" role="tablist">
        <button type="button" role="tab" aria-selected={mode === 'open'} className={'chip' + (mode === 'open' ? ' on' : '')} onClick={() => { setMode('open'); setError(''); }}>
          <Icon n="lock_open" />{t.openVault}
        </button>
        <button type="button" role="tab" aria-selected={mode === 'create'} className={'chip' + (mode === 'create' ? ' on' : '')} onClick={() => { setMode('create'); setError(''); setPath(''); }}>
          <Icon n="note_add" />{t.createVault}
        </button>
      </div>

      {mode === 'open' ? (
        <>
          {choices.length > 0 && (
            <div className="vault-choices">
              {choices.map(p => {
                const k = meta(p, fileName(p));
                return (
                  <button type="button" key={p} className={'choice' + (path === p ? ' on' : '')} onClick={() => { setPath(p); setError(''); }} title={p}>
                    <span className="vi" style={{ background: `var(${k.color})`, color: 'var(--v-on)' }}><Icon n={k.icon} /></span>
                    <span className="vault-choice-text"><b>{k.name}</b><small>{fileName(p)}</small></span>
                    {path === p && <Icon n="check_circle" fill />}
                  </button>
                );
              })}
            </div>
          )}
          {backend.desktop && (
            <button type="button" className="btn tonal" onClick={pickFile}><Icon n="folder_open" />{t.chooseFile}</button>
          )}
          {path && pwField(password, setPassword, t.masterPassword, true)}
        </>
      ) : (
        <>
          <label className="textfield">
            <Icon n="badge" />
            <input placeholder={t.vaultName} aria-label={t.vaultName} value={name} onChange={e => setName(e.target.value)} autoFocus />
          </label>
          {backend.desktop && (
            <button type="button" className="btn tonal path-btn" onClick={pickLocation} title={path}>
              <Icon n="save" /><span>{path ? fileName(path) : t.chooseLocation}</span>
            </button>
          )}
          {pwField(password, setPassword, t.masterPassword)}
          {pwField(confirm, setConfirm, t.confirmPassword)}
        </>
      )}

      {backend.desktop && (mode === 'create' || path) && (
        <div className="keyfile-row">
          <button type="button" className="btn text" onClick={pickKeyfile}><Icon n="key_vertical" />{keyfile ? fileName(keyfile) : t.keyfile}</button>
          {keyfile && <button type="button" className="icon-btn" onClick={() => setKeyfile('')} aria-label={t.remove}><Icon n="close" /></button>}
        </div>
      )}

      {error && <p className="form-error" role="alert"><Icon n="error" />{error}</p>}
      {!backend.desktop && <span className="label">{t.demoMode} · {t.masterHint}</span>}

      {quick && (
        <button type="button" className="btn tonal hello-btn" disabled={busy} onClick={hello} autoFocus>
          <Icon n="fingerprint" />{t.helloUnlock}
        </button>
      )}

      <div className="row">
        {onClose ? <button type="button" className="btn text" onClick={onClose}>{t.cancel}</button> : <span />}
        <button type="submit" className="btn filled" disabled={busy || (mode === 'create' ? (backend.desktop && !path) || !password : !path || (!password && !keyfile))}>
          <Icon n={busy ? 'hourglass_top' : mode === 'open' ? 'lock_open' : 'check'} />{mode === 'open' ? t.unlock : t.create}
        </button>
      </div>

      {/* reminder for the hybrid roadmap: server vaults are planned, not implemented */}
      <div className="wip-block" aria-disabled="true">
        <span className="label">{t.serverAccount}</span>
        <div className="wip-row">
          <button type="button" className="wip-btn" disabled><Icon n="cloud" />{t.bitwarden}<span className="pill">{t.wip}</span></button>
          <button type="button" className="wip-btn" disabled><Icon n="dns" />{t.vaultwarden}<span className="pill">{t.wip}</span></button>
        </div>
      </div>
    </form>
  );

  return modal
    ? createPortal(<div className="scrim" onClick={onClose}>{body}</div>, document.body)
    : <div className="center">{body}</div>;
}
