// Strength meter for typed passwords (master password, password field): estimate from the
// backend (same estimator as the health report), optional breach check on request.
import { useEffect, useState } from 'react';
import { backend } from './backend';
import { strengthOf } from './generator';
import type { Strings } from './i18n';
import { Icon } from './Icon';

const ICON = { weak: 'gpp_bad', medium: 'gpp_maybe', strong: 'verified_user' } as const;

export function PasswordStrength({ t, password, breachCheck }: { t: Strings; password: string; breachCheck?: boolean }) {
  // results are tagged with the password they belong to; a newer password shows none
  const [scored, setScored] = useState<{ pw: string; bits: number } | null>(null);
  const [checked, setChecked] = useState<{ pw: string; n: number | null } | null>(null);
  const bits = scored?.pw === password ? scored.bits : 0;
  const breached = checked?.pw === password ? checked.n : null;
  const setBreached = (n: number | null) => setChecked({ pw: password, n });
  const [checking, setChecking] = useState(false);
  useEffect(() => {
    if (!password) return;
    const timer = setTimeout(() => backend.passwordBits(password).then(b => setScored({ pw: password, bits: b })).catch(() => {}), 150);
    return () => clearTimeout(timer);
  }, [password]);
  if (!password) return null;
  const s = breached ? 'weak' : strengthOf(bits);
  const label = { weak: t.strengthWeak, medium: t.strengthMedium, strong: t.strengthStrong }[s];
  const check = async () => {
    setChecking(true);
    try { setBreached(await backend.passwordBreached(password)); } catch { setBreached(null); }
    setChecking(false);
  };
  return (
    <div className="pw-strength">
      <div className={'strength ' + s} title={`≈ ${bits} bit`}>
        <Icon n={ICON[s]} fill />{label}
        <span className="meter"><i style={{ transform: `scaleX(${Math.min(1, bits / 120)})` }} /></span>
      </div>
      {s === 'weak' && !breached && <small className="pw-hint">{t.masterWeakHint}</small>}
      {breached !== null && (
        <small className={'pw-hint' + (breached ? ' bad' : ' ok')}>
          <Icon n={breached ? 'gpp_maybe' : 'check_circle'} />{breached ? t.masterBreached.replace('{n}', breached.toLocaleString()) : t.masterNotBreached}
        </small>
      )}
      {breachCheck && backend.desktop && breached === null && (
        <button type="button" className="btn text" disabled={checking} onClick={check} title={t.hCheckHint}>
          <Icon n="travel_explore" />{checking ? t.hChecking : t.hCheck}
        </button>
      )}
    </div>
  );
}
