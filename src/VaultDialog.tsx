// Open / create / unlock a vault. Used as the lock screen and as the "add vault" dialog.
// Vaultwarden accounts ("bw:<server>#<email>") log in here too, including the second factor.
import { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { open as openDialog, save as saveDialog } from '@tauri-apps/plugin-dialog';
import { backend, errorCode, type VaultData } from './backend';
import type { Strings } from './i18n';
import { Icon } from './Icon';
import { PasswordStrength } from './PasswordStrength';
import { fileName, isRemote } from './ui';

export interface Known { path: string; name: string; color: string; icon: string; keyfile?: string }

const COLORS = ['--v-clay', '--v-moss', '--v-ochre'];
const ICONS = ['shield_lock', 'cottage', 'apartment', 'work_history', 'savings', 'school'];

type Mode = 'open' | 'create' | 'server';

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
  // a key file picked for this path wins over the remembered one
  const [picked, setPicked] = useState<{ path: string; file: string } | null>(null);
  // remembered key file of the selected vault (only stored when "remember key files" is on)
  const keyfile = picked?.path === path ? picked.file : known.find(k => k.path === path)?.keyfile ?? '';
  const setKeyfile = (file: string) => setPicked({ path, file });
  // quick unlock offered when this vault was locked (not closed) with the option on
  const [quickFor, setQuickFor] = useState<string | null>(null); // path that offers quick unlock
  const quick = mode === 'open' && !!path && quickFor === path;
  useEffect(() => {
    let live = true;
    if (mode === 'open' && path && backend.desktop) backend.quickAvailable(path).then(ok => { if (live) setQuickFor(ok ? path : null); }).catch(() => {});
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
  // Vaultwarden: server + email, then maybe a second factor
  const [server, setServer] = useState('https://');
  const [email, setEmail] = useState('');
  const [twoFactor, setTwoFactor] = useState<number[] | null>(null);
  const [tfProvider, setTfProvider] = useState(0);
  const [tfCode, setTfCode] = useState('');
  const [tfNote, setTfNote] = useState('');

  const meta = (p: string, n: string): Known => known.find(k => k.path === p)
    ?? (isRemote(p) ? { path: p, name: n, color: '--v-sea', icon: 'cloud' }
      : { path: p, name: n, color: COLORS[known.length % COLORS.length], icon: ICONS[known.length % ICONS.length] });

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
    if (code === 'insecure_url') return t.errInsecure;
    if (String(e).includes('kdf_insecure')) return t.errKdfInsecure;
    if (String(e).includes('kdf_weakened')) return t.errKdfWeakened;
    if (code === 'offline_no_cache') { const why = String(e).split('offline_no_cache:')[1]?.trim(); return why ? `${t.vwOffline}: ${why}` : t.vwOffline; }
    if (code === 'bw' || code === 'offline') return String(e).replace(/^(Error: )?(bw|offline):/, '');
    return code === 'hello_cancel' ? t.helloFailed : code === 'wrong_key' ? t.wrongKey : code === 'empty_key' ? t.masterPassword : `${t.fileError} (${String(e)})`;
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (mode === 'create' && password !== confirm) { setError(t.passwordsDontMatch); return; }
    const target = mode === 'server' ? `bw:${server.trim().replace(/\/+$/, '')}#${email.trim()}`
      : mode === 'create' && !backend.desktop ? `demo:${(name.trim() || 'vault').toLowerCase()}.kdbx` : path;
    if (!target) return;
    setBusy(true);
    try {
      const second: [number, string] | undefined = twoFactor && tfCode.trim() ? [tfProvider, tfCode.trim()] : undefined;
      const data = mode !== 'create'
        ? await backend.open(target, password, isRemote(target) ? undefined : keyfile || undefined, second)
        : await backend.create(target, name.trim() || fileName(target).replace(/\.kdbx$/, ''), password, keyfile || undefined);
      setPassword(''); setConfirm(''); setTwoFactor(null); setTfCode(''); setTfNote('');
      onOpened(data, { ...meta(target, data.name), name: data.name, keyfile: keyfile || undefined });
    } catch (err) {
      // file gone since last time: drop it from the remembered list
      if (mode === 'open' && errorCode(err) === 'io' && /os error [23]/.test(String(err))) {
        onMissing?.(target);
        setPath('');
      }
      if (errorCode(err) === 'twofactor') {
        const ids = String(err).split('twofactor:')[1]?.split(',').map(Number).filter(n => !isNaN(n)) ?? [];
        const usable = ids.filter(i => i === 0 || i === 1);
        setTwoFactor(ids);
        setTfProvider(usable[0] ?? 0);
        setError(usable.length ? '' : t.tfUnsupported);
        if (mode !== 'server') setPath(target);
        return;
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

      {/* what to do: a plain dropdown instead of a row of buttons that does not fit */}
      <label className="textfield mode-field">
        <Icon n={{ open: 'lock_open', create: 'note_add', server: 'dns' }[mode]} />
        <select value={mode} aria-label={t.addVault} onChange={e => {
          const m = e.target.value as Mode;
          setMode(m); setError('');
          if (m === 'create') setPath('');
          if (m === 'server') setTwoFactor(null);
        }}>
          <option value="open">{t.openVault}</option>
          <option value="create">{t.createVault}</option>
          {backend.desktop && <option value="server">{t.vwAccount}</option>}
        </select>
        <Icon n="expand_more" />
      </label>

      {mode === 'server' && (
        <>
          <p className="form-note"><Icon n="cloud" />{t.vwHint}</p>
          <label className="textfield"><Icon n="dns" />
            <input value={server} onChange={e => setServer(e.target.value)} placeholder={t.vwServer} aria-label={t.vwServer} autoFocus spellCheck={false} inputMode="url" />
          </label>
          <label className="textfield"><Icon n="mail" />
            <input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder={t.vwEmail} aria-label={t.vwEmail} autoComplete="username" />
          </label>
          {pwField(password, setPassword, t.masterPassword)}
        </>
      )}
      {twoFactor && (
        <div className="two-factor">
          <span className="label"><Icon n="verified_user" />{t.tfTitle}</span>
          {twoFactor.filter(i => i === 0 || i === 1).length > 1 && (
            <div className="seg">
              {twoFactor.filter(i => i === 0 || i === 1).map(i => (
                <button type="button" key={i} className={'chip' + (tfProvider === i ? ' on' : '')} onClick={() => setTfProvider(i)}>
                  <Icon n={i === 0 ? 'phonelink_lock' : 'mail'} />{i === 0 ? t.tfApp : t.tfEmail}
                </button>
              ))}
            </div>
          )}
          <label className="textfield"><Icon n="pin" />
            <input value={tfCode} onChange={e => setTfCode(e.target.value)} placeholder={t.tfCode} aria-label={t.tfCode} autoFocus inputMode="numeric" autoComplete="one-time-code" />
          </label>
          {tfProvider === 1 && (
            <button type="button" className="btn text" onClick={async () => {
              const target = mode === 'server' ? `bw:${server.trim().replace(/\/+$/, '')}#${email.trim()}` : path;
              try { await backend.bwSendEmail(target, password); setTfNote(t.tfSent); } catch (e) { setError(String(e)); }
            }}><Icon n="forward_to_inbox" />{t.tfSend}</button>
          )}
          {tfNote && <small className="pw-hint ok"><Icon n="check_circle" />{tfNote}</small>}
        </div>
      )}
      {mode === 'server' ? null : mode === 'open' ? (
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
            <button type="button" className="btn tonal wide" onClick={pickFile}><Icon n="folder_open" />{t.chooseFile}</button>
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
            <button type="button" className="btn tonal wide path-btn" onClick={pickLocation} title={path}>
              <Icon n="save" /><span>{path ? fileName(path) : t.chooseLocation}</span>
            </button>
          )}
          {pwField(password, setPassword, t.masterPassword)}
          <PasswordStrength t={t} password={password} breachCheck />
          {pwField(confirm, setConfirm, t.confirmPassword)}
        </>
      )}

      {backend.desktop && mode !== 'server' && (mode === 'create' || (path && !isRemote(path))) && (
        <div className="keyfile-row">
          <button type="button" className="btn text" onClick={pickKeyfile}><Icon n="key_vertical" />{keyfile ? fileName(keyfile) : t.keyfile}</button>
          {keyfile && <button type="button" className="icon-btn" onClick={() => setKeyfile('')} aria-label={t.remove}><Icon n="close" /></button>}
        </div>
      )}

      {error && <p className="form-error" role="alert"><Icon n="error" />{error}</p>}
      {!backend.desktop && <span className="label">{t.demoMode} · {t.masterHint}</span>}

      {quick && (
        <button type="button" className="btn tonal wide hello-btn" disabled={busy} onClick={hello} autoFocus>
          <Icon n="fingerprint" />{t.helloUnlock}
        </button>
      )}

      <div className="row">
        {onClose ? <button type="button" className="btn text" onClick={onClose}>{t.cancel}</button> : <span />}
        <button type="submit" className="btn filled" disabled={busy || (mode === 'server' ? !/^(https:\/\/.|http:\/\/(localhost|127\.0\.0\.1)\b)/.test(server.trim()) || !email.includes('@') || !password
          : mode === 'create' ? (backend.desktop && !path) || !password : !path || (!password && !keyfile))}>
          <Icon n={busy ? 'hourglass_top' : mode === 'create' ? 'check' : 'lock_open'} />{mode === 'create' ? t.create : t.unlock}
        </button>
      </div>

    </form>
  );

  return modal
    ? createPortal(<div className="scrim" onClick={onClose}>{body}</div>, document.body)
    : <div className="center">{body}</div>;
}
