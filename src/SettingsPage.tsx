import { useMemo, useRef, useState } from 'react';
import { DEFAULTS, SECTIONS, clamp, mergePrefs, type PrefKey, type Prefs, type Setting } from './settings';
import { settingsStrings, type SettingsStrings } from './i18n-settings';
import { LANGS, type Strings } from './i18n';

import { Icon } from './Icon';

const SCHEMA = new Map(SECTIONS.flatMap(s => s.groups.flatMap(g => g.items)).map(i => [i.key, i] as const));

export default function SettingsPage({ t, prefs, onChange, onBack, onSnack }: {
  t: Strings; prefs: Prefs; onChange: (p: Prefs) => void; onBack: () => void; onSnack: (msg: string, error?: boolean) => void;
}) {
  const ts = settingsStrings[prefs.lang];
  const [section, setSection] = useState(SECTIONS[0].id);
  const [confirmReset, setConfirmReset] = useState(false);
  const [query, setQuery] = useState('');
  const fileInput = useRef<HTMLInputElement>(null);

  // planned (not built) options stay hidden unless asked for; sections without visible options disappear
  const visible = (it: Setting) => !('planned' in it && it.planned) || prefs.showPlanned;
  const sections = useMemo(() => SECTIONS
    .map(sec => ({ ...sec, groups: sec.groups.map(g => ({ ...g, items: g.items.filter(visible) })).filter(g => g.items.length) }))
    .filter(sec => sec.groups.length), [prefs.showPlanned]); // eslint-disable-line react-hooks/exhaustive-deps
  const current = sections.find(s => s.id === section) ?? sections[0];

  // search over labels, explanations and group names in all sections
  const q = query.trim().toLowerCase();
  const results = useMemo(() => !q ? [] : sections.flatMap(sec => sec.groups.map(g => ({
    sec, g, items: g.items.filter(it => [ts.labels[it.key as keyof SettingsStrings['labels']], ts.hints[it.key as keyof SettingsStrings['hints']],
      ts.groups[g.id as keyof SettingsStrings['groups']]].some(x => x?.toLowerCase().includes(q))),
  }))).filter(r => r.items.length), [q, sections, ts]);

  const set = (key: PrefKey, value: Prefs[PrefKey]) => onChange({ ...prefs, [key]: value });

  // a setting is active only if its whole dependsOn chain is switched on
  const enabled = (s: Setting): boolean => {
    const dep = 'dependsOn' in s ? s.dependsOn : undefined;
    if (!dep) return true;
    const parent = SCHEMA.get(dep);
    return Boolean(prefs[dep]) && (!parent || enabled(parent));
  };

  const exportPrefs = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(prefs, null, 2)], { type: 'application/json' }));
    const a = Object.assign(document.createElement('a'), { href: url, download: 'anotherkeepass-settings.json' });
    a.click();
    URL.revokeObjectURL(url);
    onSnack(ts.ui.exported);
  };
  const importPrefs = async (file: File | undefined) => {
    if (!file) return;
    try {
      const raw = JSON.parse(await file.text());
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('not an object');
      onChange(mergePrefs(raw));
      onSnack(ts.ui.imported);
    } catch {
      onSnack(ts.ui.importError, true);
    }
  };
  const runAction = (key: string) => {
    if (key === 'export') exportPrefs();
    else if (key === 'import') fileInput.current?.click();
    else if (key === 'reset') setConfirmReset(true);
    else if (key === 'ksGenerate') onSnack(ts.ui.generated); // ponytail: mock; backend generates the KeeShare key pair
  };

  return (
    <div className="settings">
      <aside className="drawer settings-nav">
        <button className="btn text back" onClick={onBack}><Icon n="arrow_back" />{ts.ui.back}</button>
        <h1 className="settings-title"><Icon n="settings" fill />{ts.ui.settings}</h1>
        <label className="searchbar settings-search">
          <Icon n="search" />
          <input placeholder={ts.ui.searchSettings} value={query} onChange={e => setQuery(e.target.value)} aria-label={ts.ui.searchSettings} />
          {query && <button className="icon-btn" onClick={() => setQuery('')} aria-label={t.close}><Icon n="close" /></button>}
        </label>
        <nav className="nav">
          {sections.map(s => (
            <button key={s.id} className={'nav-item' + (s.id === current.id && !q ? ' active' : '')} onClick={() => { setSection(s.id); setQuery(''); }}>
              <span className="vi" style={{ background: 'var(--surface-highest)' }}><Icon n={s.icon} fill={s.id === current.id && !q} /></span>
              <span>{ts.sections[s.id as keyof SettingsStrings['sections']]}</span>
              <span />
            </button>
          ))}
        </nav>
        <label className="planned-toggle">
          <span><b>{ts.labels.showPlanned}</b><small>{ts.hints.showPlanned}</small></span>
          <input className="switch" type="checkbox" checked={prefs.showPlanned} onChange={e => set('showPlanned', e.target.checked)} />
        </label>
      </aside>

      <main className="pane settings-body">
        {q ? (
          <>
            <h2>{ts.ui.searchSettings}</h2>
            {!results.length && <div className="empty"><Icon n="search_off" />{ts.ui.noSettings}</div>}
            {results.map(({ sec, g, items }) => (
              <section className="set-group" key={sec.id + g.id}>
                <span className="label">{ts.sections[sec.id as keyof SettingsStrings['sections']]} · {ts.groups[g.id as keyof SettingsStrings['groups']]}</span>
                <div className="set-card">
                  {items.map(s => <Row key={s.key} s={s} ts={ts} prefs={prefs} disabled={!enabled(s)} set={set} onAction={runAction} />)}
                </div>
              </section>
            ))}
          </>
        ) : (
          <>
            <h2>{ts.sections[current.id as keyof SettingsStrings['sections']]}</h2>
            {current.groups.map(g => (
              <section className="set-group" key={g.id}>
                <span className="label">{ts.groups[g.id as keyof SettingsStrings['groups']]}</span>
                <div className="set-card">
                  {g.items.map(s => (
                    <Row key={s.key} s={s} ts={ts} prefs={prefs} disabled={!enabled(s)} set={set} onAction={runAction} />
                  ))}
                </div>
              </section>
            ))}
          </>
        )}
      </main>

      <input ref={fileInput} type="file" accept="application/json,.json" hidden
        onChange={e => { importPrefs(e.target.files?.[0]); e.target.value = ''; }} />

      {confirmReset && (
        <div className="scrim" onClick={() => setConfirmReset(false)}>
          <div className="dialog" role="alertdialog" aria-label={ts.ui.resetTitle} onClick={e => e.stopPropagation()}>
            <h3><Icon n="restart_alt" />{ts.ui.resetTitle}</h3>
            <p className="dialog-body">{ts.ui.resetBody}</p>
            <div className="row">
              <button className="btn text" onClick={() => setConfirmReset(false)}>{t.cancel}</button>
              <button className="btn filled" onClick={() => {
                // keep language and theme chosen in setup
                onChange({ ...DEFAULTS, lang: prefs.lang, theme: prefs.theme });
                setConfirmReset(false);
                onSnack(ts.ui.resetDone);
              }}>{ts.labels.reset}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Row({ s, ts, prefs, disabled, set, onAction }: {
  s: Setting; ts: SettingsStrings; prefs: Prefs; disabled: boolean;
  set: (key: PrefKey, value: Prefs[PrefKey]) => void; onAction: (key: string) => void;
}) {
  const label = ts.labels[s.key as keyof SettingsStrings['labels']];
  const hint = ts.hints[s.key as keyof SettingsStrings['hints']];
  const id = 'set-' + s.key;
  const indent = 'dependsOn' in s && s.dependsOn;
  const badges = (
    <>
      {'platform' in s && s.platform && <span className="pill">{s.platform === 'windows' ? ts.ui.windows : ts.ui.linuxMac}</span>}
      {'planned' in s && s.planned && <span className="pill desk" title={ts.ui.plannedHint}><Icon n="schedule" />{ts.ui.planned}</span>}
    </>
  );

  if (s.type === 'action') {
    return (
      <div className={'set-row' + (s.wip ? ' wip' : '')}>
        <div className="set-text"><span className="set-label">{label}</span>{hint && <span className="set-hint">{hint}</span>}<span className="set-badges">{badges}</span></div>
        {s.wip ? (
          <button className='wip-btn' disabled><Icon n={s.key === 'bwConnect' ? 'cloud' : 'dns'} />{label}<span className='pill'>{ts.ui.wip}</span></button>
        ) : (
          <button className={'btn ' + (s.key === 'reset' ? 'outlined' : 'tonal')} onClick={() => onAction(s.key)}>
            <Icon n={{ export: 'download', import: 'upload', reset: 'restart_alt', ksGenerate: 'key', bwConnect: 'cloud', vwConnect: 'dns' }[s.key]} />{label}
          </button>
        )}
      </div>
    );
  }

  if (s.type === 'info') {
    return (
      <div className={'set-row' + (indent ? ' indent' : '')}>
        <div className="set-text"><span className="set-label">{label}</span></div>
        <code className="set-info">{s.value}</code>
      </div>
    );
  }

  const value = prefs[s.key];
  let control: React.ReactNode;
  if (s.type === 'toggle') {
    control = <input id={id} className="switch" type="checkbox" checked={value as boolean} disabled={disabled}
      onChange={e => set(s.key, e.target.checked)} />;
  } else if (s.type === 'number') {
    control = <NumberField id={id} s={s} value={value as number} disabled={disabled} unit={s.unit === 'd' ? ts.ui.days : s.unit}
      onCommit={n => set(s.key, n)} />;
  } else if (s.type === 'select') {
    control = (
      <select id={id} className="set-select" value={value as string} disabled={disabled} onChange={e => set(s.key, e.target.value)}>
        {s.options.map(o => (
          <option key={o} value={o}>
            {s.key === 'lang' ? LANGS.find(l => l.id === o)?.name : ts.options[o as keyof SettingsStrings['options']]}
          </option>
        ))}
      </select>
    );
  } else if (s.type === 'shortcut') {
    control = <ShortcutField id={id} value={value as string} disabled={disabled} ts={ts} onChange={v => set(s.key, v)} />;
  } else {
    control = (
      <span className="set-path">
        <input id={id} className="set-input" value={value as string} disabled={disabled}
          onChange={e => set(s.key, e.target.value)} spellCheck={false} />
        {s.type === 'path' && (
          // ponytail: browsers cannot return file paths; Tauri dialog plugin fills this in the desktop app
          <button className="icon-btn" disabled title={ts.ui.desktopHint} aria-label={ts.ui.browse}><Icon n="folder_open" /></button>
        )}
      </span>
    );
  }

  return (
    <div className={'set-row' + (indent ? ' indent' : '') + (disabled ? ' off' : '')}>
      <label className="set-text" htmlFor={id}>
        <span className="set-label">{label}</span>
        {hint && <span className="set-hint">{hint}</span>}
        <span className="set-badges">{badges}</span>
      </label>
      {control}
    </div>
  );
}

function NumberField({ id, s, value, disabled, unit, onCommit }: {
  id: string; s: Extract<Setting, { type: 'number' }>; value: number; disabled: boolean; unit: string; onCommit: (n: number) => void;
}) {
  const [text, setText] = useState(String(value));
  const [lastValue, setLastValue] = useState(value);
  if (value !== lastValue) { setLastValue(value); setText(String(value)); } // external change (reset/import)
  const commit = () => {
    const n = clamp(Number(text) || s.min, s.min, s.max);
    setText(String(n));
    if (n !== value) onCommit(n);
  };
  return (
    <span className="set-number">
      <input id={id} type="number" min={s.min} max={s.max} step={s.step ?? 1} value={text} disabled={disabled}
        onChange={e => setText(e.target.value)} onBlur={commit} onKeyDown={e => e.key === 'Enter' && commit()} />
      {unit && <span>{unit}</span>}
    </span>
  );
}

function ShortcutField({ id, value, disabled, ts, onChange }: {
  id: string; value: string; disabled: boolean; ts: SettingsStrings; onChange: (v: string) => void;
}) {
  const [listening, setListening] = useState(false);
  return (
    <span className="set-path">
      <input id={id} className="set-input shortcut" readOnly disabled={disabled}
        value={listening ? ts.ui.pressKeys : value || '—'}
        onFocus={() => setListening(true)} onBlur={() => setListening(false)}
        onKeyDown={e => {
          e.preventDefault();
          if (e.key === 'Escape') { (e.target as HTMLInputElement).blur(); return; }
          if (['Control', 'Shift', 'Alt', 'Meta'].includes(e.key)) return; // wait for the actual key
          const combo = [e.ctrlKey && 'Ctrl', e.altKey && 'Alt', e.shiftKey && 'Shift', e.metaKey && 'Meta',
            e.key.length === 1 ? e.key.toUpperCase() : e.key].filter(Boolean).join('+');
          onChange(combo);
          (e.target as HTMLInputElement).blur();
        }} />
      {value && <button className="icon-btn" disabled={disabled} onClick={() => onChange('')} aria-label={ts.ui.clearShortcut}><Icon n="close" /></button>}
    </span>
  );
}
