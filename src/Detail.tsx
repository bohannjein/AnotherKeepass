// Detail pane of an entry: view and edit fields, TOTP, tags, attachments, history.
import { lazy, useState, useRef, useEffect, Suspense, useCallback } from 'react';
import { type Totp, type VaultData, backend } from './backend';
import { type FieldKind, type Field, type Item, type VaultInfo, type Folder, type Draft, type Attachment } from './model';
import { openExternal } from './open';
import { strengthOf } from './generator';
import { colorize } from './colorize';
import { type Strings } from './i18n';
import { type Prefs } from './settings';
import { settingsStrings } from './i18n-settings';
import { Icon } from './Icon';
import { SshPanel } from './SshPanel';
import { previewable } from './ui';
import { TotpSetup } from './TotpSetup';
import { useContextMenu } from './ContextMenu';
import { today } from './ui';
import { ItemAvatar } from './ItemList';

export const Generator = lazy(() => import('./GeneratorDialog'));
const FIELD_ICON: Partial<Record<keyof Strings, string>> = {
  username: 'person', password: 'key', website: 'language', cardholder: 'badge', number: 'credit_card',
  expires: 'event', cvc: 'password', pin: 'pin', totp: 'timer', noteBody: 'notes',
  fullName: 'person', email: 'mail', phone: 'call', address: 'home', birthdate: 'cake',
};
const MULTILINE = new Set<keyof Strings>(['noteBody', 'address']);

/** Free tags; Enter or comma adds, Backspace on empty input removes the last one. */
function TagEditor({ t, tags, onChange }: { t: Strings; tags: string[]; onChange: (tags: string[]) => void }) {
  const [text, setText] = useState('');
  const add = () => {
    const v = text.trim().replace(/[,;]/g, '');
    if (v && !tags.includes(v) && v !== 'pinned') onChange([...tags, v]);
    setText('');
  };
  return (
    <div className="field tag-editor">
      <Icon n="sell" />
      <div>
        <span className="label">{t.tags}</span>
        <div className="tag-input">
          {tags.map(tg => (
            <span key={tg} className="badge tag">{tg}
              <button type="button" onClick={() => onChange(tags.filter(x => x !== tg))} aria-label={`${t.remove}: ${tg}`}><Icon n="close" /></button>
            </span>
          ))}
          <input value={text} placeholder={t.addTag} aria-label={t.addTag} onChange={e => setText(e.target.value)} onBlur={add}
            onKeyDown={e => {
              if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); add(); }
              else if (e.key === 'Backspace' && !text && tags.length) onChange(tags.slice(0, -1));
            }} />
        </div>
      </div>
    </div>
  );
}

const KIND_ICON: Record<FieldKind, string> = {
  text: 'short_text', hidden: 'visibility_off', totp: 'lock_clock', date: 'calendar_month', url: 'language',
};
const ADDABLE: { kind: FieldKind; name: keyof Strings }[] = [
  { kind: 'text', name: 'fieldText' },
  { kind: 'totp', name: 'fieldTotp' },
  { kind: 'hidden', name: 'fieldHidden' },
  { kind: 'date', name: 'fieldDate' },
];

const fieldName = (t: Strings, f: Field) => (f.key ? t[f.key] : f.label) || t.fieldText;
const fieldIcon = (f: Field) => (f.key && FIELD_ICON[f.key]) || KIND_ICON[f.kind ?? 'text'];
const isSecret = (f: Field) => f.kind === 'hidden' || f.kind === 'totp';
const fmtSize = (n: number) => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
const fmtDate = (iso: string) => new Date(iso.length > 10 ? iso : iso + 'T00:00').toLocaleDateString(document.documentElement.lang);

/** Polls the backend for the current TOTP code while `enabled`. */
function useTotp(get: (() => Promise<Totp>) | undefined, enabled: boolean) {
  const [s, setS] = useState<Totp | null>(null);
  const getRef = useRef(get);
  useEffect(() => { getRef.current = get; });
  useEffect(() => {
    if (!enabled || !getRef.current) return;
    let live = true;
    const tick = () => getRef.current?.().then(v => live && setS(v)).catch(() => live && setS(null));
    tick();
    const id = setInterval(tick, 1000);
    return () => { live = false; clearInterval(id); };
  }, [enabled]);
  return s;
}

function FieldRow({ t, f, prefs, onCopy, reveal, totp, onEdit, strength }: {
  t: Strings; f: Field; prefs: Prefs; onCopy: () => void; onEdit: () => void; strength?: () => Promise<number>;
  reveal?: () => Promise<string>; totp?: () => Promise<Totp>;
}) {
  const isPw = f.key === 'password';
  const isNote = f.key === 'noteBody';
  // which fields start masked in the preview (reveal via eye button)
  const maskable = f.kind === 'hidden' || (f.kind === 'totp' && prefs.hideTotpPreview) || (isNote && prefs.hideNotesPreview);
  const [shown, setShown] = useState(() => f.kind === 'hidden' ? isPw && !prefs.hidePwPreview : !maskable);
  // protected values are fetched from the backend only when shown
  const [secret, setSecret] = useState<string | null>(f.protected && !f.loaded && f.kind !== 'totp' ? null : f.value);
  useEffect(() => {
    if (shown && secret === null && reveal) reveal().then(setSecret).catch(() => setSecret(''));
  }, [shown, secret, reveal]);
  // revealed secrets mask themselves again after a while and leave the UI's memory
  useEffect(() => {
    if (!shown || !maskable || !prefs.revealSeconds) return;
    const timer = setTimeout(() => { setShown(false); if (f.protected && !f.loaded) setSecret(null); }, prefs.revealSeconds * 1000);
    return () => clearTimeout(timer);
  }, [shown, maskable, prefs.revealSeconds, f.protected, f.loaded]);
  const otp = useTotp(totp, f.kind === 'totp' && !(maskable && !shown));
  const [bits, setBits] = useState<number | null>(null);
  // short "copied" pulse on the row
  const [flash, setFlash] = useState(false);
  const copy = () => { onCopy(); setFlash(true); setTimeout(() => setFlash(false), 650); };
  useEffect(() => { if (strength) strength().then(setBits).catch(() => {}); }, [strength]);
  const openMenu = useContextMenu();
  const menu = (e: React.MouseEvent) => openMenu(e, [
    { icon: 'content_copy', label: t.copy, action: onCopy },
    ...(maskable ? [{ icon: shown ? 'visibility_off' : 'visibility', label: shown ? t.hide : t.show, action: () => setShown(s => !s) }] : []),
    ...(f.kind === 'url' && f.value ? [{ icon: 'open_in_new', label: t.scOpenUrl, action: () => openExternal(f.value) }] : []),
    'sep',
    { icon: 'edit', label: t.edit, kbd: 'Ctrl+E', action: onEdit },
  ]);
  const name = fieldName(t, f);
  const masked = maskable && !shown;
  const value = secret ?? '';
  const urlAction = () => {
    if (prefs.urlDoubleClick === 'open') openExternal(f.value);
    else if (prefs.urlDoubleClick === 'edit') onEdit();
    else onCopy();
  };
  const code = otp?.code ?? '';
  const val =
    isPw && secret === '' ? (prefs.passwordPlaceholder ? '••••••••' : '')
    : f.kind === 'url' ? <a href={f.value} target="_blank" rel="noreferrer" onClick={e => { e.stopPropagation(); e.preventDefault(); openExternal(f.value); }}>{f.value}</a>
    : f.kind === 'totp' ? (
      <span className="otp">
        {masked ? '••• •••' : code ? `${code.slice(0, Math.ceil(code.length / 2))} ${code.slice(Math.ceil(code.length / 2))}` : '— — —'}
        {otp && !masked && <i className="ring" style={{ '--p': otp.remaining / otp.period } as React.CSSProperties}>{otp.remaining}</i>}
      </span>
    )
    : masked || secret === null ? '••••••••'
    : f.kind === 'hidden' && prefs.colorizePasswords ? colorize(value)
    : f.kind === 'date' && value ? fmtDate(value)
    : value;
  const mono = isSecret(f) || (isNote && prefs.monospaceNotes);
  const multi = f.key && MULTILINE.has(f.key);
  return (
    // whole row copies (click or double-click per settings); inner controls stop propagation
    <div className={'field copyable' + (flash ? ' copied' : '')} role="button" tabIndex={0} title={prefs.copyOnDoubleClick ? undefined : t.clickToCopy}
      aria-label={`${t.copy}: ${name}`} onContextMenu={menu}
      onClick={prefs.copyOnDoubleClick ? undefined : copy}
      onDoubleClick={f.kind === 'url' ? urlAction : prefs.copyOnDoubleClick ? copy : undefined}
      onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); copy(); } }}>
      <Icon n={fieldIcon(f)} />
      <div>
        <span className="label">{name}</span>
        <div className={'val' + (mono ? ' mono' : '') + (multi ? ' multi' : '')}
          title={!multi && !isSecret(f) && typeof val === 'string' ? val : undefined}>{val}</div>
        {bits !== null && bits > 0 && (
          <span className={'field-strength ' + strengthOf(bits)} title={`≈ ${bits} bit`}>
            <i style={{ transform: `scaleX(${Math.min(1, bits / 120)})` }} />
          </span>
        )}
      </div>
      <div className="tools">
        {maskable && (
          <button className="icon-btn" title={shown ? t.hide : t.show} aria-label={shown ? t.hide : t.show}
            onClick={e => { e.stopPropagation(); setShown(s => !s); }}
            onDoubleClick={e => e.stopPropagation()} onKeyDown={e => e.stopPropagation()}>
            <Icon n={shown ? 'visibility_off' : 'visibility'} />
          </button>
        )}
        <span className="copy-hint" aria-hidden><Icon n="content_copy" /></span>
      </div>
    </div>
  );
}

function EditRow({ t, f, prefs, title, onChange, onRemove, onCopy }: {
  t: Strings; f: Field; prefs: Prefs; title: string; onChange: (f: Field) => void; onRemove?: () => void;
  onCopy: (text: string, what: string) => void;
}) {
  const [shown, setShown] = useState(!prefs.hideInEdit);
  const [gen, setGen] = useState(false);
  const canGenerate = f.key === 'password' || (f.kind === 'hidden' && !f.key);
  const type = f.kind === 'date' ? 'date' : f.kind === 'url' ? 'url' : isSecret(f) && !shown ? 'password' : 'text';
  return (
    <div className="field">
      <Icon n={fieldIcon(f)} />
      <div>
        {f.key ? <span className="label">{t[f.key]}</span> : (
          <input className="label-edit" value={f.label ?? ''} placeholder={t.fieldName} aria-label={t.fieldName}
            onChange={e => onChange({ ...f, label: e.target.value, raw: undefined })} />
        )}
        {f.key && MULTILINE.has(f.key) ? (
          // textarea keeps newlines; <input> would strip them on save
          <textarea className="val edit" rows={4} value={f.value} aria-label={fieldName(t, f)}
            onChange={e => onChange({ ...f, value: e.target.value })} />
        ) : f.kind === 'totp' ? (
          <TotpSetup t={t} value={f.value} title={title} onChange={value => onChange({ ...f, value })}>
            <input className="val edit mono" type={type} value={f.value} aria-label={fieldName(t, f)} placeholder="otpauth://… / JBSWY3DP…"
              autoComplete="off" spellCheck={false} onChange={e => onChange({ ...f, value: e.target.value })} />
          </TotpSetup>
        ) : (
          <input className={'val edit' + (isSecret(f) ? ' mono' : '')} type={type} value={f.value} aria-label={fieldName(t, f)}
            autoComplete="off" spellCheck={false} onChange={e => onChange({ ...f, value: e.target.value })} />
        )}
      </div>
      <div className="tools">
        {canGenerate && (
          <button type="button" className="icon-btn" title={t.genOpen} aria-label={t.genOpen} onClick={() => setGen(true)}>
            <Icon n="password" />
          </button>
        )}
        {gen && <Suspense fallback={null}><Generator t={t} onClose={() => setGen(false)} onCopy={onCopy} onUse={(pw: string) => onChange({ ...f, value: pw })} /></Suspense>}
        {isSecret(f) && !(f.key && MULTILINE.has(f.key)) && (
          <button type="button" className="icon-btn" aria-label={shown ? t.hide : t.show} onClick={() => setShown(s => !s)}>
            <Icon n={shown ? 'visibility_off' : 'visibility'} />
          </button>
        )}
        {onRemove && (
          <button type="button" className="icon-btn" title={t.remove} aria-label={t.remove} onClick={onRemove}>
            <Icon n="delete" />
          </button>
        )}
      </div>
    </div>
  );
}

export function Detail({ t, item, vault: v, folders, isNew, prefs, onCopyField, onCopyText, loadSecrets, getTotp, onDuplicate, onSave, onDiscard,
  onTrash, onRestore, onDeleteForever, onTogglePin, onHistoryRestore, onDownload, onPreview, onLoadIcon, onRemoveIcon, onSshChanged, onMessage }: {
  t: Strings; item: Item; vault: VaultInfo; folders: Folder[]; isNew: boolean; prefs: Prefs;
  onCopyField: (f: Field, what: string) => void; onCopyText: (text: string, what: string) => void;
  loadSecrets: () => Promise<Record<string, string>>; getTotp: (field: string) => Promise<Totp>; onDuplicate: () => void;
  onSave: (d: Draft) => Promise<boolean>; onDiscard: () => void;
  onTrash: () => void; onRestore: () => void; onDeleteForever: () => void; onTogglePin: () => void;
  onHistoryRestore: (index: number) => void; onDownload: (a: Attachment) => void; onPreview: (a: Attachment) => void;
  onLoadIcon?: () => void; onRemoveIcon?: () => void;
  onSshChanged?: (d: VaultData) => void; onMessage: (msg: string, error?: boolean) => void;
}) {
  const [moreMenu, setMoreMenu] = useState(false);
  const fromItem = (): Draft => ({
    title: item.title, folder: item.folder ?? '', note: item.note ?? '', expires: item.expires ?? null, tags: item.tags ?? [],
    fields: item.fields.map(f => ({ ...f })), attachments: item.attachments ?? [],
  });
  const [draft, setDraft] = useState<Draft | null>(() => isNew ? fromItem() : null); // non-null = edit mode
  const [busy, setBusy] = useState(false);
  const [menu, setMenu] = useState(false);
  const [dragging, setDragging] = useState(false);
  const d = draft ?? fromItem();
  const folderName = folders.find(f => f.id === item.folder)?.name;
  const ms = settingsStrings[prefs.lang].ui;

  // reveal one protected field (cached per detail view)
  const secrets = useRef<Promise<Record<string, string>> | null>(null);
  const getSecrets = () => {
    if (!secrets.current) {
      secrets.current = loadSecrets();
      setTimeout(() => { secrets.current = null; }, 30_000); // don't keep decrypted values around
    }
    return secrets.current;
  };
  const revealer = (raw: string) => () => getSecrets().then(s => s[raw] ?? '');
  const passwordBits = useCallback(() => backend.entryPasswordBits(item.vault, item.id), [item.vault, item.id, item.modified]); // eslint-disable-line react-hooks/exhaustive-deps

  const startEdit = async () => {
    const next = fromItem();
    if (next.fields.some(f => f.protected)) {
      const s = await getSecrets();
      next.fields = next.fields.map(f => f.protected && f.raw ? { ...f, value: s[f.raw] ?? '', loaded: true } : f);
    }
    setDraft(next);
  };
  const save = async () => {
    setBusy(true);
    const ok = await onSave(draft!);
    setBusy(false);
    if (ok && !isNew) { secrets.current = null; setDraft(null); }
  };
  const cancel = () => { setMenu(false); if (isNew) onDiscard(); else setDraft(null); };
  const keys = useRef({ startEdit: () => {}, cancel: () => {}, editing: false, trashed: false });
  useEffect(() => { keys.current = { startEdit, cancel, editing: !!draft, trashed: !!item.trashed }; });
  useEffect(() => {
    const edit = () => { if (!keys.current.editing && !keys.current.trashed) keys.current.startEdit(); };
    const esc = () => { if (keys.current.editing) keys.current.cancel(); };
    window.addEventListener('akp:edit', edit);
    window.addEventListener('akp:cancel', esc);
    return () => { window.removeEventListener('akp:edit', edit); window.removeEventListener('akp:cancel', esc); };
  }, []);
  const patch = (p: Partial<Draft>) => setDraft(x => ({ ...x!, ...p }));
  const setField = (idx: number, f: Field) => patch({ fields: d.fields.map((x, i) => i === idx ? f : x) });
  const addField = (kind: FieldKind, name: keyof Strings) => {
    patch({ fields: [...d.fields, { label: t[name], value: '', kind }] });
    setMenu(false);
  };
  const addFiles = (files: FileList | null) => {
    if (!files?.length) return;
    patch({ attachments: [...d.attachments, ...[...files].map(f => ({ name: f.name, size: f.size, file: f }))] });
  };
  const viewFields = d.fields.filter(f => f.protected || f.value);
  const expired = !!item.expires && item.expires < today();

  return (
    <>
      <header>
        <div className="hero">
          <ItemAvatar item={item} letters={prefs.letterAvatars} />
          <div>
            {draft ? (
              <input className="title-edit" value={draft.title} placeholder={t.title} aria-label={t.title} autoFocus={isNew}
                onChange={e => patch({ title: e.target.value })} />
            ) : <h2 title={item.title}>{item.title || t.untitled}</h2>}
            <div className="meta">
              <span className="badge" style={{ background: `var(${v.color})`, color: 'var(--v-on)' }}><Icon n={v.icon} />{v.name}</span>
              {draft ? (
                <label className="badge select">
                  <Icon n="folder" />
                  <select value={draft.folder} onChange={e => patch({ folder: e.target.value })} aria-label={t.folder}>
                    <option value="">{t.noFolder}</option>
                    {folders.map(f => <option key={f.id} value={f.id}>{f.name}</option>)}
                  </select>
                </label>
              ) : folderName && <span className="badge"><Icon n="folder" />{folderName}</span>}
              <span className="badge">{t[item.type]}</span>
              {item.pinned && <span className="badge"><Icon n="push_pin" />{t.pinned}</span>}
              {!draft && item.tags?.map(tg => <span key={tg} className="badge tag"><Icon n="sell" />{tg}</span>)}
              {!draft && item.expires && (
                <span className={'badge' + (expired ? ' danger' : '')}><Icon n={expired ? 'event_busy' : 'event'} />
                  {expired ? t.expired : `${t.expiresOn} ${fmtDate(item.expires)}`}</span>
              )}
              {item.trashed && <span className="badge danger"><Icon n="delete" />{t.trash}</span>}
            </div>
          </div>
        </div>
        <div className="actions">
          {draft ? (
            <>
              <button className="btn text" onClick={cancel}>{t.cancel}</button>
              <button className="btn filled" onClick={save} disabled={busy}><Icon n={busy ? 'hourglass_top' : 'check'} />{t.save}</button>
            </>
          ) : (
            <>
              {item.trashed
                ? <button className="btn filled" onClick={onRestore}><Icon n="restore_from_trash" />{t.restore}</button>
                : <button className="btn filled" onClick={startEdit}><Icon n="edit" />{t.edit}</button>}
              <span className="more-wrap">
                <button className="icon-btn tonal" aria-label={t.more} aria-expanded={moreMenu} onClick={() => setMoreMenu(m => !m)}>
                  <Icon n="more_vert" />
                </button>
                {moreMenu && (
                  <>
                    <div className="menu-scrim" onClick={() => setMoreMenu(false)} />
                    <div className="menu more-menu" role="menu">
                      {!item.trashed && (
                        <button role="menuitem" onClick={() => { setMoreMenu(false); onTogglePin(); }}>
                          <Icon n="push_pin" />{item.pinned ? t.unpinItem : t.pinItem}
                        </button>
                      )}
                      {!item.trashed && (
                        <button role="menuitem" onClick={() => { setMoreMenu(false); onDuplicate(); }}>
                          <Icon n="content_copy" />{t.duplicate}<kbd>Ctrl+D</kbd>
                        </button>
                      )}
                      {!item.trashed && onLoadIcon && (
                        <button role="menuitem" onClick={() => { setMoreMenu(false); onLoadIcon(); }}>
                          <Icon n="image_search" />{t.loadIcon}
                        </button>
                      )}
                      {!item.trashed && onRemoveIcon && (
                        <button role="menuitem" onClick={() => { setMoreMenu(false); onRemoveIcon(); }}>
                          <Icon n="hide_image" />{t.removeIcon}
                        </button>
                      )}
                      {item.trashed ? (
                        <button role="menuitem" onClick={() => { setMoreMenu(false); onDeleteForever(); }}>
                          <Icon n="delete_forever" />{t.deleteForever}
                        </button>
                      ) : (
                        <button role="menuitem" onClick={() => { setMoreMenu(false); onTrash(); }}>
                          <Icon n="delete" />{ms.moveToTrash}
                        </button>
                      )}
                    </div>
                  </>
                )}
              </span>
            </>
          )}
        </div>
      </header>

      {(draft ? d.fields : viewFields).length > 0 && (
        <div className={'fields' + (draft ? ' editing' : '')}>
          {draft
            ? d.fields.map((f, idx) => (
              <EditRow key={idx} t={t} f={f} prefs={prefs} title={d.title} onCopy={onCopyText} onChange={nf => setField(idx, nf)}
                onRemove={f.key ? undefined : () => patch({ fields: d.fields.filter((_, i) => i !== idx) })} />
            ))
            : viewFields.map(f => (
              <FieldRow key={f.raw ?? fieldName(t, f)} t={t} f={f} prefs={prefs} onEdit={startEdit}
                onCopy={() => onCopyField(f, fieldName(t, f))}
                reveal={f.protected && f.raw && !isNew ? revealer(f.raw) : undefined}
                strength={f.key === 'password' && !isNew ? passwordBits : undefined}
                totp={f.kind === 'totp' && !isNew && f.raw ? () => getTotp(f.raw!) : undefined} />
            ))}
        </div>
      )}

      {draft && (
        <div className="add-more">
          <button className="btn text" onClick={() => setMenu(m => !m)} aria-expanded={menu}><Icon n="add" />{t.addMore}</button>
          {menu && (
            <div className="menu" role="menu">
              {ADDABLE.map(a => (
                <button key={a.kind} role="menuitem" onClick={() => addField(a.kind, a.name)}>
                  <Icon n={KIND_ICON[a.kind]} />{t[a.name]}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {draft ? (
        <div className="fields editing section">
          <TagEditor t={t} tags={d.tags} onChange={tags => patch({ tags })} />
          <div className="field">
            <Icon n="sticky_note_2" />
            <div>
              <span className="label">{t.noteBody}</span>
              <textarea className="val edit" rows={3} placeholder={t.addNote} value={d.note}
                onChange={e => patch({ note: e.target.value })} aria-label={t.noteBody} />
            </div>
          </div>
          <div className="field expiry-row">
            <Icon n="event" />
            <div>
              <span className="label">{t.expiry}</span>
              <input className="val edit" type="date" value={d.expires ?? ''} disabled={d.expires === null}
                onChange={e => patch({ expires: e.target.value || null })} aria-label={t.expiresOn} />
            </div>
            <input className="switch" type="checkbox" checked={d.expires !== null} aria-label={t.expiry}
              onChange={e => patch({ expires: e.target.checked ? new Date(Date.now() + 90 * 86_400_000).toISOString().slice(0, 10) : null })} />
          </div>
        </div>
      ) : d.note && (
        <div className="fields section">
          <FieldRow t={t} f={{ key: 'noteBody', value: d.note, raw: 'Notes' }} prefs={prefs} onEdit={startEdit}
            onCopy={() => onCopyField({ key: 'noteBody', value: d.note, raw: 'Notes' }, t.noteBody)} />
        </div>
      )}

      {(draft || d.attachments.length > 0) && (
        <div className="attach section">
          <div className="attach-head">
            <Icon n="attach_file" />
            <div><b>{t.attachments}</b>{draft && <small>{t.attachmentsHint}</small>}</div>
          </div>
          {d.attachments.map((a, idx) => (
            <div className="file-row" key={idx}>
              <Icon n="description" />
              <span><b>{a.name}</b><small>{fmtSize(a.size)}</small></span>
              {previewable(a.name) && <button className="icon-btn" title={t.preview} aria-label={t.preview} onClick={() => onPreview(a)}><Icon n="visibility" /></button>}
              <button className="icon-btn" title={t.download} aria-label={t.download} onClick={() => onDownload(a)}><Icon n="download" /></button>
              {draft && (
                <button className="icon-btn" title={t.remove} aria-label={t.remove}
                  onClick={() => patch({ attachments: d.attachments.filter((_, i) => i !== idx) })}>
                  <Icon n="delete" />
                </button>
              )}
            </div>
          ))}
          {draft && (
            <label className={'dropzone' + (dragging ? ' over' : '')}
              onDragOver={e => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={e => { e.preventDefault(); setDragging(false); addFiles(e.dataTransfer.files); }}>
              <Icon n="upload" />{t.dropFiles}
              <input type="file" multiple hidden onChange={e => { addFiles(e.target.files); e.target.value = ''; }} />
            </label>
          )}
        </div>
      )}

      {!draft && !isNew && onSshChanged && d.attachments.length > 0 && (
        <SshPanel t={t} vault={item.vault} id={item.id} files={d.attachments.map(a => a.name)} onChanged={onSshChanged} onMessage={onMessage} />
      )}

      {!isNew && (
        <details className="more">
          <summary><Icon n="info" />{t.moreInfo}<Icon n="expand_more" /></summary>
          <dl>
            <dt>{t.modified}</dt><dd>{item.modified ? fmtDate(item.modified) : '—'}</dd>
            <dt>{t.file}</dt><dd title={v.id}>{v.file}</dd>
            <dt>UUID</dt><dd className="mono">{item.id}</dd>
          </dl>
          <div className="history">
            <span className="label">{t.history}</span>
            {!item.history?.length && <small>{t.noHistory}</small>}
            {item.history?.map((when, i) => (
              <div className="history-row" key={i}>
                <Icon n="history" />
                <span>{when ? new Date(when).toLocaleString(document.documentElement.lang) : '—'}</span>
                <button className="btn text" onClick={() => onHistoryRestore(i)}>{t.restoreVersion}</button>
              </div>
            ))}
          </div>
        </details>
      )}
    </>
  );
}
