// "New entry" button in the menu: entry types, templates, password, folder, import.
import { useState } from 'react';
import { type Field, type ItemType } from './model';
import { type Strings } from './i18n';
import { Icon } from './Icon';
import { NEW_TYPES, TYPE_ICON } from './ui';

/** extra entry layouts built from custom fields (labels in the user's language at creation time) */
const TEMPLATE_PRESETS: { id: string; type: ItemType; icon: string; label: 'tplWifi' | 'tplLicense' | 'tplBank' | 'tplServer'; fields: (t: Strings) => Field[] }[] = [
  { id: 'wifi', type: 'other', icon: 'wifi', label: 'tplWifi', fields: t => [{ label: t.fSsid, value: '' }, { key: 'password', value: '', kind: 'hidden' }, { label: t.fSecurity, value: 'WPA2/WPA3' }] },
  { id: 'license', type: 'other', icon: 'license', label: 'tplLicense', fields: t => [{ label: t.fProduct, value: '' }, { label: t.fLicenseKey, value: '', kind: 'hidden', protected: true }, { key: 'email', value: '' }, { label: t.fVersion, value: '' }] },
  { id: 'bank', type: 'other', icon: 'account_balance', label: 'tplBank', fields: t => [{ label: t.fHolder, value: '' }, { label: t.fIban, value: '' }, { label: t.fBic, value: '' }, { key: 'username', value: '' }, { key: 'password', value: '', kind: 'hidden' }, { key: 'pin', value: '', kind: 'hidden' }] },
  { id: 'server', type: 'login', icon: 'dns', label: 'tplServer', fields: t => [{ label: t.fHost, value: '' }, { label: t.fPort, value: '22' }, { key: 'username', value: '' }, { key: 'password', value: '', kind: 'hidden' }, { key: 'website', value: '', kind: 'url' }] },
];

export function NewMenu({ t, onCreate, onGenerator, onFolder, onImport }: {
  t: Strings; onCreate: (type: ItemType, fields?: Field[]) => void;
  onGenerator: () => void; onFolder: () => void; onImport: () => void;
}) {
  const [open, setOpen] = useState(false);
  const pick = (fn: () => void) => () => { setOpen(false); fn(); };
  return (
    <div className="new-wrap">
      <button className="fab" onClick={() => setOpen(m => !m)} aria-expanded={open}><Icon n="add" /><span className="fab-label">{t.newItem}</span></button>
      {open && (
        <>
          <div className="menu-scrim" onClick={() => setOpen(false)} />
          <div className="menu new-menu" role="menu">
            {NEW_TYPES.map(type => (
              <button key={type} role="menuitem" onClick={pick(() => onCreate(type))}>
                <span className={'avatar sm ' + type}><Icon n={TYPE_ICON[type]} /></span>{t[type]}
              </button>
            ))}
            <span className="menu-label">{t.templates}</span>
            {TEMPLATE_PRESETS.map(p => (
              <button key={p.id} role="menuitem" onClick={pick(() => onCreate(p.type, p.fields(t)))}>
                <span className="avatar sm other"><Icon n={p.icon} /></span>{t[p.label]}
              </button>
            ))}
            <hr />
            <button role="menuitem" onClick={pick(onGenerator)}>
              <span className="avatar sm pin"><Icon n="password" /></span>{t.password}
            </button>
            <button role="menuitem" onClick={pick(onFolder)}>
              <span className="avatar sm other"><Icon n="create_new_folder" /></span>{t.folder}
            </button>
            <button role="menuitem" onClick={pick(onImport)}>
              <span className="avatar sm note"><Icon n="upload_file" /></span>{t.importItems}
            </button>
          </div>
        </>
      )}
    </div>
  );
}
