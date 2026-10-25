// Password health view: report from Rust, optional breach counts (Have I Been Pwned) and the
// issue filter. Breach results belong to the vault state they were computed for.
import { useCallback, useEffect, useState } from 'react';
import { backend, type Health, type VaultData } from './backend';
import { ISSUES, issueName as issueNameOf, type Issue } from './HealthOverview';
import { type Strings } from './i18n';
import { type Notify } from './useSnack';

export function useHealth({ t, active, open, notify }: { t: Strings; active: boolean; open: Record<string, VaultData>; notify: Notify }) {
  const [health, setHealth] = useState<Record<string, Health>>({});
  // tagged with the `open` object they were checked against: any vault change drops them
  const [checked, setChecked] = useState<{ open: object; found: Record<string, number> } | null>(null);
  const breaches = checked?.open === open ? checked.found : null;
  const [checking, setChecking] = useState(false);
  const [issue, setIssue] = useState<Issue | null>(null);
  useEffect(() => {
    if (!active) return;
    backend.healthReport().then(r => setHealth(Object.fromEntries(r.map(h => [h.id, h])))).catch(() => {});
  }, [active, open]);

  const issuesOf = useCallback((id: string): Issue[] => {
    const h = health[id];
    if (!h) return [];
    return ISSUES.filter(k => k === 'breached' ? (breaches?.[id] ?? 0) > 0 : k === 'reused' ? h.reused > 0 : h[k]);
  }, [health, breaches]);
  const issueName = (k: Issue) => issueNameOf(t, k);
  const issueLabel = (k: Issue, id: string) => {
    if (k === 'breached') return `${(breaches?.[id] ?? 0).toLocaleString()} ${t.hBreachedN}`;
    if (k === 'reused') return `${t.hReused} (${(health[id]?.reused ?? 0) + 1}×)`;
    return issueName(k);
  };

  // HIBP range API with k-anonymity: only 5 hex chars of each SHA-1 leave the machine
  const checkBreaches = async () => {
    setChecking(true);
    try {
      const prefixes = await backend.breachPrefixes();
      const ranges: Record<string, string> = {};
      for (let i = 0; i < prefixes.length; i += 6) {
        await Promise.all(prefixes.slice(i, i + 6).map(async p => {
          const r = await fetch(`https://api.pwnedpasswords.com/range/${p}`, { headers: { 'Add-Padding': 'true' } });
          if (!r.ok) throw new Error(`HTTP ${r.status}`);
          ranges[p] = await r.text();
        }));
      }
      const found = await backend.breachMatch(ranges);
      setChecked({ open, found });
      if (!Object.keys(found).length) notify(t.hNoBreaches);
      else setIssue('breached');
    } catch (e) { notify(`${t.hCheck}: ${String(e)}`, true); }
    setChecking(false);
  };

  const healthCounts = {
    ok: Object.keys(health).filter(id => !issuesOf(id).length).length,
    ...Object.fromEntries(ISSUES.map(k => [k, Object.keys(health).filter(id => issuesOf(id).includes(k)).length])),
  } as Record<Issue | 'ok', number>;

  return { health, breaches, checking, issue, setIssue, issuesOf, issueName, issueLabel, checkBreaches, healthCounts };
}
