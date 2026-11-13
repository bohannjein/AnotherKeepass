import { useState } from 'react';
import { backend } from './backend';
import { Icon } from './Icon';
import { Select } from './Select';
import { openExternal } from './open';
import { yubikeyError } from './yubikeyError';
import type { Strings } from './i18n';

type Status = { kind: 'idle' } | { kind: 'busy' } | { kind: 'ok'; text: string } | { kind: 'error'; text: string };

/**
 * The YubiKey choice of a vault: slot (off, 1, 2), a button that tries the key, and an
 * explanation of how a slot is set up. The app itself never writes to the key.
 */
export function YubiKeyField({ t, value, onChange }: { t: Strings; value: string; onChange: (slot: string) => void }) {
  // the result belongs to the slot it was tried with: another slot starts blank
  const [result, setResult] = useState<{ slot: string; status: Status } | null>(null);
  const status: Status = result?.slot === value ? result.status : { kind: 'idle' };
  const [help, setHelp] = useState(false);

  const check = async () => {
    const slot = value;
    setResult({ slot, status: { kind: 'busy' } });
    try {
      const info = await backend.yubikeyCheck(slot);
      setResult({ slot, status: { kind: 'ok', text: t.ykOk.replace('{n}', String(info.serial)).replace('{s}', slot) } });
    } catch (e) {
      setResult({ slot, status: { kind: 'error', text: yubikeyError(t, e) } });
    }
  };

  return (
    <div className="yk-field">
      <div className="yk-row">
        <span className="yk-label"><Icon n="usb" />{t.yubikey}</span>
        <Select value={value} ariaLabel={t.yubikey} onChange={onChange} options={[
          { value: '', label: t.yubikeyOff },
          { value: '1', label: `${t.yubikeySlot} 1` },
          { value: '2', label: `${t.yubikeySlot} 2` },
        ]} />
      </div>
      <p className="yk-hint">{t.yubikeyHint}</p>
      {value && (
        <div className="yk-test">
          <button type="button" className="btn tonal" onClick={check} disabled={status.kind === 'busy'}>
            <Icon n={status.kind === 'busy' ? 'hourglass_top' : 'verified_user'} />{t.ykCheck}
          </button>
          <span className={'yk-status ' + status.kind} role="status">
            {status.kind === 'busy' && t.ykChecking}
            {status.kind === 'ok' && <><Icon n="check_circle" />{status.text}</>}
            {status.kind === 'error' && <><Icon n="error" />{status.text}</>}
          </span>
        </div>
      )}
      <button type="button" className="yk-help-toggle" aria-expanded={help} onClick={() => setHelp(h => !h)}>
        <Icon n="chevron_right" />{t.ykHelp}
      </button>
      {help && (
        <div className="yk-help">
          <ol>
            <li>{t.ykStep1.split('yubico.com').flatMap((part, i) => i === 0 ? [part] : [
              <a key={i} href="https://www.yubico.com/support/download/" onClick={e => { e.preventDefault(); openExternal(e.currentTarget.href); }}>yubico.com</a>, part])}</li>
            <li>{t.ykStep2}</li>
            <li>{t.ykStep3}</li>
          </ol>
          <div className="yk-safe">
            <b><Icon n="warning" />{t.ykSafeTitle}</b>
            <ul>
              <li>{t.ykSafe1}</li>
              <li>{t.ykSafe2}</li>
              <li>{t.ykSafe3}</li>
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}
