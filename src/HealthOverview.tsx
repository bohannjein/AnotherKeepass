// Password health: big score ring + one tile per problem kind (detail pane),
// and list rows with colored issue pills. Data comes from App (flags from Rust).
import type { Strings } from './i18n';
import { Icon } from './Icon';
import type { Item } from './model';

export type Issue = 'breached' | 'weak' | 'reused' | 'old' | 'expired';
export const ISSUES: Issue[] = ['breached', 'weak', 'reused', 'old', 'expired'];
export const ISSUE_ICON: Record<Issue, string> = {
  breached: 'gpp_maybe', weak: 'key_off', reused: 'repeat', old: 'hourglass_bottom', expired: 'event_busy',
};
export const issueName = (t: Strings, k: Issue) =>
  ({ breached: t.hBreached, weak: t.hWeak, reused: t.hReused, old: t.hOld, expired: t.hExpired })[k];
const issueHint = (t: Strings, k: Issue) =>
  ({ breached: t.hBreachedHint, weak: t.hWeakHint, reused: t.hReusedHint, old: t.hOldHint, expired: t.hExpiredHint })[k];

export function HealthOverview({ t, total, counts, breachesChecked, checking, canCheck, onCheck, active, onPick }: {
  t: Strings; total: number; counts: Record<Issue | 'ok', number>; breachesChecked: boolean; checking: boolean; canCheck: boolean;
  onCheck: () => void; active: Issue | null; onPick: (k: Issue | null) => void;
}) {
  const bad = total - counts.ok;
  const score = total ? Math.round((counts.ok / total) * 100) : 100;
  const mood = score >= 90 ? 'good' : score >= 60 ? 'ok' : 'bad';
  const r = 54, c = 2 * Math.PI * r;
  return (
    <div className="health">
      <div className={'health-hero ' + mood}>
        <div className="health-ring">
          <svg viewBox="0 0 128 128" aria-hidden>
            <circle cx="64" cy="64" r={r} className="track" />
            <circle cx="64" cy="64" r={r} className="value" strokeDasharray={c} strokeDashoffset={c * (1 - score / 100)} />
          </svg>
          <div><b>{score}</b><span>%</span></div>
        </div>
        <div className="health-mood">
          <h2>{mood === 'good' ? t.hMoodGood : mood === 'ok' ? t.hMoodOk : t.hMoodBad}</h2>
          <p>{counts.ok} / {total} {t.hSummary}{bad > 0 && <> · <b>{bad}</b> {t.hToFix}</>}</p>
        </div>
      </div>
      <div className="health-tiles">
        {ISSUES.map(k => {
          const n = counts[k];
          const unchecked = k === 'breached' && !breachesChecked;
          return (
            <button key={k} className={`health-tile ${k}${n ? '' : ' clear'}${active === k ? ' on' : ''}`}
              disabled={!n && !unchecked} onClick={() => unchecked ? onCheck() : onPick(active === k ? null : k)}>
              <span className="health-icon"><Icon n={n || unchecked ? ISSUE_ICON[k] : 'check'} fill={!!n} /></span>
              <b>{unchecked ? (checking ? '…' : '?') : n}</b>
              <span className="health-name">{issueName(t, k)}</span>
              <small>{unchecked ? (checking ? t.hChecking : canCheck ? t.hCheck : t.hNotChecked) : n ? issueHint(t, k) : t.hAllGood}</small>
            </button>
          );
        })}
      </div>
      {breachesChecked || <p className="health-note"><Icon n="info" />{t.hCheckHint}</p>}
    </div>
  );
}

/** List row in the health view: avatar tinted by the worst issue, one pill per issue. */
export function HealthRow({ t, item, issues, label, active, onClick }: {
  t: Strings; item: Item; issues: Issue[]; label: (k: Issue) => string; active: boolean; onClick: () => void;
}) {
  return (
    <button className={'item health-item' + (active ? ' active' : '')} onClick={onClick}>
      <span className={'avatar issue-' + issues[0]}><Icon n={ISSUE_ICON[issues[0]]} fill /></span>
      <span>
        <b>{item.title || t.untitled}</b>
        <span className="issue-pills">
          {issues.map(k => <span key={k} className={'issue-pill ' + k}><Icon n={ISSUE_ICON[k]} />{label(k)}</span>)}
        </span>
      </span>
    </button>
  );
}
