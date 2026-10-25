// Small dialogs of the main window: folders, shortcuts, browser requests, Auto-Type picker, key file, vault look.
import { useState } from 'react';
import { createPortal } from 'react-dom';
import { type BrowserAsk, type AutoTypePick } from './backend';
import { type VaultInfo, type Folder, type Item } from './model';
import { type Strings } from './i18n';
import { Icon } from './Icon';
import { PasswordStrength } from './PasswordStrength';
import { isRemote } from './ui';
import { type Confirm } from './useItemActions';

export function FolderDialog({ t, mode, name: initialName, vault: initialVault, vaults, folders, parent: initialParent, onClose, onSubmit }: {
  t: Strings; mode: 'create' | 'rename'; name: string; vault: string; vaults: VaultInfo[]; folders: Folder[]; parent: string;
  onClose: () => void; onSubmit: (vault: string, name: string, parent: string) => void;
}) {
  const [name, setName] = useState(initialName);
  const [vault, setVault] = useState(initialVault);
  const [parent, setParent] = useState(initialParent);
  const options = folders.filter(f => f.vault === vault);
  return (
    <div className="scrim" onClick={onClose}>
      <form className="dialog" role="dialog" aria-label={mode === 'create' ? t.newFolder : t.renameFolder} onClick={e => e.stopPropagation()}
        onSubmit={e => { e.preventDefault(); if (name.trim()) onSubmit(vault, name.trim(), parent); }}>
        <h3><Icon n={mode === 'create' ? 'create_new_folder' : 'drive_file_rename_outline'} />{mode === 'create' ? t.newFolder : t.renameFolder}</h3>
        <label className="textfield">
          <Icon n="folder" />
          <input autoFocus placeholder={t.folderName} aria-label={t.folderName} value={name} onChange={e => setName(e.target.value)} />
        </label>
        {mode === 'create' && vaults.length > 1 && (
          <>
            <span className="label">{t.vault}</span>
            <div className="choices">
              {vaults.map(v => (
                <button type="button" key={v.id} className={'choice' + (vault === v.id ? ' on' : '')} onClick={() => { setVault(v.id); setParent(''); }}>
                  {v.name}{vault === v.id && <Icon n="check_circle" fill />}
                </button>
              ))}
            </div>
          </>
        )}
        {mode === 'create' && options.length > 0 && (
          <label className="opt">{t.parentFolder}
            <select className="set-select" value={parent} onChange={e => setParent(e.target.value)}>
              <option value="">{vaults.find(v => v.id === vault)?.name ?? '—'}</option>
              {options.map(f => <option key={f.id} value={f.id}>{f.name}</option>)}
            </select>
          </label>
        )}
        <div className="row">
          <button type="button" className="btn text" onClick={onClose}>{t.cancel}</button>
          <button type="submit" className="btn filled" disabled={!name.trim()}><Icon n="check" />{mode === 'create' ? t.create : t.rename}</button>
        </div>
      </form>
    </div>
  );
}

const SHORTCUTS: [string, keyof Strings][] = [
  ['Ctrl+F', 'scSearch'], ['Ctrl+N', 'scNew'], ['Ctrl+E', 'scEdit'], ['Ctrl+B', 'scCopyUser'], ['Ctrl+C', 'scCopyPw'],
  ['Ctrl+T', 'scCopyTotp'], ['Ctrl+U', 'scOpenUrl'], ['Ctrl+D', 'scDuplicate'], ['Ctrl+Shift+V', 'autoType'], ['Entf / Del', 'scTrash'],
  ['↑ ↓', 'scNavigate'], ['Esc', 'scCancel'], ['Ctrl+L', 'scLock'], ['F1', 'scHelp'],
];

export function ShortcutsDialog({ t, onClose }: { t: Strings; onClose: () => void }) {
  return createPortal(
    <div className="scrim" onClick={onClose}>
      <div className="dialog" role="dialog" aria-label={t.shortcuts} onClick={e => e.stopPropagation()}>
        <h3><Icon n="keyboard" />{t.shortcuts}</h3>
        <dl className="shortcut-list">
          {SHORTCUTS.map(([keys, label]) => (
            <div key={keys}><dt><kbd>{keys}</kbd></dt><dd>{t[label]}</dd></div>
          ))}
        </dl>
        <small className="label">{t.dragHint}</small>
        <div className="row"><button className="btn filled" onClick={onClose}>{t.close}</button></div>
      </div>
    </div>, document.body);
}

/** Confirmations the browser extension needs: new connection, access to logins, updating a login. */
export function BrowserAskDialog({ t, ask, vaultName, onAnswer }: {
  t: Strings; ask: BrowserAsk; vaultName: (id: string) => string; onAnswer: (answer: unknown) => void;
}) {
  const [name, setName] = useState(() => 'browser-' + new Date().toISOString().slice(0, 10));
  const [allow, setAllow] = useState<string[]>(ask.kind === 'access' ? ask.entries.map(e => e.uuid) : []);
  const [remember, setRemember] = useState(true);
  const [target, setTarget] = useState<string | null>(null); // passkey: entry to update / to sign in with
  const deny = () => onAnswer(null);
  return createPortal(
    <div className="scrim">
      <div className="dialog browser-ask" role="alertdialog" aria-label={t.brAccessTitle}
        onKeyDown={e => { if (e.key === 'Escape') { e.stopPropagation(); deny(); } }}>
        {ask.kind === 'associate' && (
          <form onSubmit={e => { e.preventDefault(); if (name.trim()) onAnswer({ name: name.trim() }); }} className="browser-ask-form">
            <h3><Icon n="extension" />{t.brAssocTitle}</h3>
            <p className="dialog-body">{t.brAssocBody}</p>
            <label className="textfield"><Icon n="badge" />
              <input autoFocus value={name} onChange={e => setName(e.target.value)} aria-label={t.brAssocName} placeholder={t.brAssocName} />
            </label>
            <div className="row">
              <button type="button" className="btn text" onClick={deny}>{t.brDeny}</button>
              <button type="submit" className="btn filled" disabled={!name.trim()}><Icon n="link" />{t.brAllowSave}</button>
            </div>
          </form>
        )}
        {ask.kind === 'access' && (
          <>
            <h3><Icon n="travel_explore" />{t.brAccessTitle}</h3>
            <p className="dialog-body">{t.brAccessBody} <b>{ask.host}</b></p>
            <div className="browser-ask-list">
              {ask.entries.map(e => (
                <label key={e.uuid} className="opt">
                  <span className="browser-ask-entry"><b>{e.title || t.untitled}</b><small>{[e.username, vaultName(e.vault)].filter(Boolean).join(' · ')}</small></span>
                  <input className="switch" type="checkbox" checked={allow.includes(e.uuid)}
                    onChange={ev => setAllow(a => ev.target.checked ? [...a, e.uuid] : a.filter(x => x !== e.uuid))} />
                </label>
              ))}
            </div>
            <label className="opt">{t.brRemember}<input className="switch" type="checkbox" checked={remember} onChange={e => setRemember(e.target.checked)} /></label>
            <div className="row">
              <button className="btn text" onClick={() => onAnswer({ allow: [], remember })}>{t.brDeny}</button>
              <button className="btn filled" autoFocus onClick={() => onAnswer({ allow, remember })}><Icon n="check" />{t.brAllow}</button>
            </div>
          </>
        )}
        {ask.kind === 'passkeyRegister' && (
          <>
            <h3><Icon n="passkey" />{t.pkRegTitle}</h3>
            <p className="dialog-body">{t.pkRegBody} <b>{ask.rpId}</b>{ask.username && <> ({ask.username})</>}</p>
            {ask.existing.length > 0 && (
              <div className="browser-ask-list">
                {[{ uuid: '', title: t.pkRegNew, username: '', vault: '' }, ...ask.existing].map(e => (
                  <label key={e.uuid || 'new'} className="opt">
                    <span className="browser-ask-entry"><b>{e.uuid ? `${t.pkRegReplace} ${e.title || t.untitled}` : e.title}</b>
                      <small>{[e.username, e.vault && vaultName(e.vault)].filter(Boolean).join(' · ')}</small></span>
                    <input type="radio" name="pk-target" checked={(target ?? '') === e.uuid} onChange={() => setTarget(e.uuid)} />
                  </label>
                ))}
              </div>
            )}
            <div className="row">
              <button className="btn text" onClick={deny}>{t.cancel}</button>
              <button className="btn filled" autoFocus onClick={() => onAnswer({ ok: true, uuid: target || null })}><Icon n="check" />{t.pkSave}</button>
            </div>
          </>
        )}
        {ask.kind === 'passkeyGet' && (
          <>
            <h3><Icon n="passkey" />{t.pkGetTitle}</h3>
            <p className="dialog-body">{t.pkGetBody} <b>{ask.rpId}</b></p>
            <div className="browser-ask-list">
              {ask.entries.map(e => (
                <label key={e.uuid} className="opt">
                  <span className="browser-ask-entry"><b>{e.title || t.untitled}</b><small>{[e.username, vaultName(e.vault)].filter(Boolean).join(' · ')}</small></span>
                  <input type="radio" name="pk-pick" checked={(target ?? ask.entries[0]?.uuid) === e.uuid} onChange={() => setTarget(e.uuid)} />
                </label>
              ))}
            </div>
            <div className="row">
              <button className="btn text" onClick={deny}>{t.cancel}</button>
              <button className="btn filled" autoFocus onClick={() => onAnswer({ uuid: target ?? ask.entries[0]?.uuid })}><Icon n="login" />{t.pkUse}</button>
            </div>
          </>
        )}
        {ask.kind === 'delete' && (
          <>
            <h3><Icon n="delete" />{t.brDeleteTitle}</h3>
            <p className="dialog-body">{t.brDeleteBody}: <b>{ask.title || t.untitled}</b>{ask.username && <> ({ask.username})</>}</p>
            <div className="row">
              <button className="btn filled" autoFocus onClick={deny}>{t.cancel}</button>
              <button className="btn text danger" onClick={() => onAnswer({ ok: true })}><Icon n="delete" />{t.remove}</button>
            </div>
          </>
        )}
        {ask.kind === 'update' && (
          <>
            <h3><Icon n="sync_lock" />{t.brUpdateTitle}</h3>
            <p className="dialog-body">{t.brUpdateBody}: <b>{ask.title || t.untitled}</b>{ask.username && <> ({ask.username})</>}</p>
            <div className="row">
              <button className="btn text" onClick={deny}>{t.cancel}</button>
              <button className="btn filled" autoFocus onClick={() => onAnswer({ ok: true })}><Icon n="check" />{t.brUpdate}</button>
            </div>
          </>
        )}
      </div>
    </div>, document.body);
}

/** Entry choice for a global Auto-Type: matches first, otherwise search all entries. */
export function AutoTypePicker({ t, pick, items, vaultName, onPick, onClose }: {
  t: Strings; pick: AutoTypePick; items: Item[]; vaultName: (id: string) => string;
  onPick: (vault: string, id: string, sequence: string | null) => void; onClose: () => void;
}) {
  const [q, setQ] = useState('');
  const query = q.trim().toLowerCase();
  const rows = pick.candidates.length && !query
    ? pick.candidates.map(c => ({ vault: c.vault, id: c.id, title: c.title, sub: c.username, sequence: c.sequence as string | null }))
    : items.filter(i => !query || (i.title + ' ' + i.subtitle).toLowerCase().includes(query)).slice(0, 50)
      .map(i => ({ vault: i.vault, id: i.id, title: i.title, sub: i.subtitle, sequence: null }));
  return createPortal(
    <div className="scrim" onClick={onClose}>
      <div className="dialog autotype-dialog" role="dialog" aria-label={t.autoType} onClick={e => e.stopPropagation()}>
        <h3><Icon n="keyboard" />{t.autoTypePick}</h3>
        <p className="dialog-body autotype-window" title={pick.windowTitle}>{pick.windowTitle || '—'}</p>
        {!pick.candidates.length && <small className="label">{t.autoTypeNone}</small>}
        <label className="textfield">
          <Icon n="search" />
          <input autoFocus placeholder={t.search} aria-label={t.search} value={q} onChange={e => setQ(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && rows[0]) onPick(rows[0].vault, rows[0].id, rows[0].sequence); }} />
        </label>
        <div className="autotype-list">
          {rows.map(r => (
            <button key={r.vault + r.id} className="item" onClick={() => onPick(r.vault, r.id, r.sequence)}>
              <span className="avatar login"><Icon n="person" /></span>
              <span><b>{r.title || t.untitled}</b><span>{[r.sub, vaultName(r.vault)].filter(Boolean).join(' · ')}</span></span>
            </button>
          ))}
          {!rows.length && <div className="empty"><Icon n="eco" />{t.noItems}</div>}
        </div>
        <div className="row"><button className="btn text" onClick={onClose}>{t.cancel}</button></div>
      </div>
    </div>, document.body);
}

export function KeyDialog({ t, onClose, onSubmit }: { t: Strings; onClose: () => void; onSubmit: (pw: string) => void }) {
  const [pw, setPw] = useState('');
  const [confirm, setConfirm] = useState('');
  const mismatch = confirm.length > 0 && pw !== confirm;
  return (
    <div className="scrim" onClick={onClose}>
      <form className="dialog" role="dialog" aria-label={t.changeMasterKey} onClick={e => e.stopPropagation()}
        onSubmit={e => { e.preventDefault(); if (pw && pw === confirm) onSubmit(pw); }}>
        <h3><Icon n="key" />{t.changeMasterKey}</h3>
        <label className="textfield"><Icon n="key" />
          <input type="password" autoFocus placeholder={t.masterPassword} aria-label={t.masterPassword} value={pw} onChange={e => setPw(e.target.value)} />
        </label>
        <PasswordStrength t={t} password={pw} breachCheck />
        <label className="textfield"><Icon n="key" />
          <input type="password" placeholder={t.confirmPassword} aria-label={t.confirmPassword} value={confirm} onChange={e => setConfirm(e.target.value)} />
        </label>
        {mismatch && <p className="form-error" role="alert"><Icon n="error" />{t.passwordsDontMatch}</p>}
        <div className="row">
          <button type="button" className="btn text" onClick={onClose}>{t.cancel}</button>
          <button type="submit" className="btn filled" disabled={!pw || pw !== confirm}><Icon n="check" />{t.save}</button>
        </div>
      </form>
    </div>
  );
}

const VAULT_COLORS = ['--v-clay', '--v-moss', '--v-ochre', '--v-plum', '--v-sea', '--v-sand'];
const VAULT_ICONS = ['shield_lock', 'cottage', 'apartment', 'work', 'savings', 'school', 'family_restroom', 'sports_esports', 'code', 'favorite', 'flight', 'storefront'];
export function VaultLookDialog({ t, vault, onClose, onSave }: { t: Strings; vault: VaultInfo; onClose: () => void; onSave: (color: string, icon: string) => void }) {
  const [color, setColor] = useState(vault.color);
  const [icon, setIcon] = useState(vault.icon);
  return createPortal(
    <div className="scrim" onClick={onClose}>
      <div className="dialog vault-look" role="dialog" aria-label={t.vaultLook} onClick={e => e.stopPropagation()}>
        <h3><span className="vi big" style={{ background: `var(${color})` }}><Icon n={icon} /></span>{vault.name}</h3>
        <span className="label">{t.vaultColor}</span>
        <div className="swatches">
          {VAULT_COLORS.map(c => <button key={c} className={'swatch' + (c === color ? ' on' : '')} style={{ background: `var(${c})` }} onClick={() => setColor(c)} aria-label={c} />)}
        </div>
        <span className="label">{t.vaultIcon}</span>
        <div className="icon-grid">
          {VAULT_ICONS.map(i => <button key={i} className={'icon-pick' + (i === icon ? ' on' : '')} onClick={() => setIcon(i)} aria-label={i}><Icon n={i} /></button>)}
        </div>
        <div className="row">
          <button className="btn text" onClick={onClose}>{t.cancel}</button>
          <button className="btn filled" onClick={() => onSave(color, icon)}><Icon n="check" />{t.save}</button>
        </div>
      </div>
    </div>, document.body);
}

/** Link a .kdbx vault with an unlocked Vaultwarden account for two-way sync (or unlink it). */
export function SyncDialog({ t, vaultList, syncWith, onLink, onClose }: {
  t: Strings; vaultList: VaultInfo[]; syncWith?: string | null; onLink: (remote: string | null) => void; onClose: () => void;
}) {
  const accounts = vaultList.filter(x => isRemote(x.id) && !x.locked);
  return createPortal(
    <div className="scrim" onClick={onClose}>
      <div className="dialog share-dialog" role="dialog" aria-label={t.syncTitle} onClick={e => e.stopPropagation()}>
        <h3><Icon n="sync_alt" />{t.syncTitle}</h3>
        <p className="dialog-body">{t.syncBody}</p>
        {accounts.length ? (
          <div className="share-modes">
            {accounts.map(x => (
              <button key={x.id} className={'choice' + (syncWith === x.id ? ' on' : '')} onClick={() => onLink(x.id)}>
                <Icon n="cloud" /><span><b>{x.name}</b><small>{syncWith === x.id ? t.syncChip + ' ' + x.name : t.syncStart}</small></span>
              </button>
            ))}
          </div>
        ) : <p className="form-note"><Icon n="info" />{t.syncNone}</p>}
        <div className="row">
          {syncWith && <button className="btn text danger" onClick={() => onLink(null)}>{t.syncStop}</button>}
          <span style={{ flex: 1 }} />
          <button className="btn text" onClick={onClose}>{t.close}</button>
        </div>
      </div>
    </div>, document.body);
}

/** Yes/no question before a destructive action. */
export function ConfirmDialog({ t, confirm, onClose }: { t: Strings; confirm: Confirm; onClose: () => void }) {
  return (
    <div className="scrim" onClick={onClose}>
      <div className="dialog" role="alertdialog" aria-label={confirm.title} onClick={e => e.stopPropagation()}>
        <h3><Icon n={confirm.icon} />{confirm.title}</h3>
        <p className="dialog-body">{confirm.body}</p>
        <div className="row">
          <button className="btn text" onClick={onClose}>{t.cancel}</button>
          <button className="btn filled" onClick={() => { confirm.action(); onClose(); }}><Icon n={confirm.icon} />{confirm.label}</button>
        </div>
      </div>
    </div>
  );
}
