import { Select } from './Select';
import { useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { DEFAULTS, SECTIONS, clamp, mergePrefs, onThisPlatform, type PrefKey, type Prefs, type Setting } from './settings';
import { settingsStrings, type SettingsStrings } from './i18n-settings';
import { LANGS, type Strings } from './i18n';

import { Icon } from './Icon';
import { backend } from './backend';
import { SCHEMES, colorsOf, contrast, prefersDark, resolveTheme, type Colors, type Mode } from './schemes';
import { type UpdateState } from './useUpdates';

const SCHEMA = new Map(SECTIONS.flatMap(s => s.groups.flatMap(g => g.items)).map(i => [i.key, i] as const));

export default function SettingsPage({ t, prefs, onChange, onBack, onSnack, update, onCheckUpdate, onInstallUpdate }: {
  t: Strings; prefs: Prefs; onChange: (p: Prefs) => void; onBack: () => void; onSnack: (msg: string, error?: boolean) => void;
  update: UpdateState | null; onCheckUpdate: (manual: boolean) => Promise<UpdateState | null>; onInstallUpdate: () => void;
}) {
  const ts = settingsStrings[prefs.lang];
  const [section, setSection] = useState(SECTIONS[0].id);
  const [confirmReset, setConfirmReset] = useState(false);
  const [query, setQuery] = useState('');
  // live SSH agent status for the SSH section
  const [sshState, setSsh] = useState<{ path: string; reachable: boolean } | null>(null);
  const sshShown = section === 'ssh' && prefs.sshEnabled;
  const ssh = sshShown ? sshState : null;
  useEffect(() => {
    if (!sshShown) return;
    backend.sshStatus(prefs.sshAuthSock).then(setSsh).catch(() => setSsh(null));
  }, [sshShown, prefs.sshAuthSock]);
  const fileInput = useRef<HTMLInputElement>(null);

  // Store package: the Store installs updates, so the update options go
  const [packaged, setPackaged] = useState(false);
  useEffect(() => { backend.packaged().then(setPackaged).catch(() => {}); }, []);
  const STORE_HIDDEN = ['updateAuto', 'updateNotify', 'updateBeta', 'updateNow'];
  // planned (not built) options never show; sections without visible options disappear
  const visible = (it: Setting) => onThisPlatform(it) && !('planned' in it && it.planned) && !(packaged && STORE_HIDDEN.includes(it.key));
  const sections = useMemo(() => SECTIONS
    .map(sec => ({ ...sec, groups: sec.groups.map(g => ({ ...g, items: g.items.filter(visible) })).filter(g => g.items.length) }))
    .filter(sec => sec.groups.length), [packaged]); // eslint-disable-line react-hooks/exhaustive-deps
  const current = sections.find(s => s.id === section) ?? sections[0];

  // search over labels, explanations and group names in all sections
  const q = query.trim().toLowerCase();
  const results = useMemo(() => !q ? [] : sections.flatMap(sec => sec.groups.map(g => ({
    sec, g, items: g.items.filter(it => [ts.labels[it.key as keyof SettingsStrings['labels']], ts.hints[it.key as keyof SettingsStrings['hints']],
      ts.groups[g.id as keyof SettingsStrings['groups']]].some(x => x?.toLowerCase().includes(q))),
  }))).filter(r => r.items.length), [q, sections, ts]);

  const [confirmHello, setConfirmHello] = useState(false);
  const set = (key: PrefKey, value: Prefs[PrefKey]) => {
    // Windows Hello replaces the master passwords: only after an explicit OK
    if (key === 'helloUnlock' && value === true && !prefs.helloUnlock) { setConfirmHello(true); return; }
    // connecting the browser sets up the installed ones (the single list is under Advanced)
    if (key === 'browserEnabled' && value === true) {
      backend.browsersDetected()
        .then(found => onChange({ ...prefs, browserEnabled: true, ...Object.fromEntries(found.map(k => [k, true])) }))
        .catch(() => onChange({ ...prefs, browserEnabled: true }));
      return;
    }
    onChange({ ...prefs, [key]: value });
  };
  const patch = (p: Partial<Prefs>) => onChange({ ...prefs, ...p });
  // "Advanced" at the end of a section, closed by default
  const [advOpen, setAdvOpen] = useState<string | null>(null);
  // a switch with sub-options folds open in place (arrow turns down, the card grows)
  const [openSubs, setOpenSubs] = useState<string[]>([]);
  const toggleSub = (key: string) => setOpenSubs(o => o.includes(key) ? o.filter(k => k !== key) : [...o, key]);

  // a setting is active only if its whole dependsOn chain is switched on
  // visible sub-options of a switch (advanced ones stay under Advanced)
  const childrenOf = (key: string) => SECTIONS.flatMap(x => x.groups.flatMap(g => g.items))
    .filter(i => visible(i) && !i.advanced && 'dependsOn' in i && i.dependsOn === key);
  const isChild = (i: Setting) => {
    const dep = 'dependsOn' in i ? i.dependsOn : undefined;
    return !!dep && !SCHEMA.get(dep)?.advanced && childrenOf(dep).some(c => c.key === i.key);
  };
  // "On · Open the last vault on start" / "Off"
  const summary = (key: PrefKey) => {
    if (!prefs[key]) return ts.ui.off;
    const on = childrenOf(key).filter(c => c.type === 'toggle' && prefs[c.key]).map(c => ts.labels[c.key as keyof SettingsStrings['labels']]);
    return [ts.ui.on, ...on].join(' · ');
  };
  const enabled = (s: Setting): boolean => {
    if (s.key === 'systemDark') return prefs.theme === 'system';
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
      // paths that end up in the browser manifest, backups or the SSH agent are not taken from a file
      onChange({ ...mergePrefs(raw), bCustomProxy: prefs.bCustomProxy, bProxyPath: prefs.bProxyPath, backupPath: prefs.backupPath, sshAuthSock: prefs.sshAuthSock });
      onSnack(ts.ui.imported);
    } catch {
      onSnack(ts.ui.importError, true);
    }
  };
  const runAction = (key: string) => {
    if (key === 'export') exportPrefs();
    else if (key === 'import') fileInput.current?.click();
    else if (key === 'reset') setConfirmReset(true);
    else if (key === 'layoutReset') { onChange({ ...prefs, drawerWidth: DEFAULTS.drawerWidth, listWidth: DEFAULTS.listWidth }); onSnack(ts.ui.layoutDone); }
    else if (key === 'updateNow' && update) onInstallUpdate();
    else if (key === 'updateNow') onCheckUpdate(true)
      .then(u => onSnack(u ? (u.ready ? t.updateReady : t.updateAvailable).replace('{v}', u.version) : t.updateNone))
      .catch(() => onSnack(t.updateFailed, true));
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
            <button key={s.id} className={'nav-item' + (s.block ? ' block' : '') + (s.id === current.id && !q ? ' active' : '')}
              onClick={() => { setSection(s.id); setQuery(''); }}>
              <span className="vi" style={{ background: `var(${s.tint})` }}><Icon n={s.icon} fill /></span>
              <span>{ts.sections[s.id as keyof SettingsStrings['sections']]}</span>
            </button>
          ))}
        </nav>
      </aside>

      <main className="pane settings-body" key={q ? 'search' : current.id}>
        {q ? (
          <>
            <h2>{ts.ui.searchSettings}</h2>
            {!results.length && <div className="empty"><Icon n="search_off" />{ts.ui.noSettings}</div>}
            {results.map(({ sec, g, items }) => (
              <section className="set-group" key={sec.id + g.id}>
                <span className="label">{ts.sections[sec.id as keyof SettingsStrings['sections']]} · {ts.groups[g.id as keyof SettingsStrings['groups']]}</span>
                <div className="set-card">
                  {items.map(s => <Row key={s.key} s={s} ts={ts} prefs={prefs} disabled={!enabled(s)} set={set} patch={patch} onAction={runAction} t={t} ssh={ssh}
                    button={s.key === 'updateNow' && update ? (update.installable ? t.updateInstall : t.updateOpenPage) : undefined} />)}
                </div>
              </section>
            ))}
          </>
        ) : (
          <>
            <h2>
              <span className="vi" style={{ background: `var(${current.tint})` }}><Icon n={current.icon} fill /></span>
              {ts.sections[current.id as keyof SettingsStrings['sections']]}
            </h2>
            {current.groups.map(g => {
              // sub-options live on their switch's page
              const items = g.items.filter(i => !i.advanced && enabled(i) && !(isChild(i)));
              if (!items.length) return null;
              return (
                <section className="set-group" key={g.id}>
                  <span className="label">{ts.groups[g.id as keyof SettingsStrings['groups']]}</span>
                  <div className="set-card">
                    {items.map(s => childrenOf(s.key).length > 0
                      ? <SubRow key={s.key} label={ts.labels[s.key as keyof SettingsStrings['labels']]}
                        summary={summary(s.key as PrefKey)} open={openSubs.includes(s.key)} onToggle={() => toggleSub(s.key)}>
                        {[s, ...childrenOf(s.key)].map(c => <Row key={c.key} s={c} ts={ts} prefs={prefs} disabled={!enabled(c)} set={set} patch={patch} onAction={runAction} t={t} ssh={ssh} quiet flat />)}
                      </SubRow>
                      : <Row key={s.key} s={s} ts={ts} prefs={prefs} disabled={!enabled(s)} set={set} patch={patch} onAction={runAction} t={t} ssh={ssh} quiet
                        button={s.key === 'updateNow' && update ? (update.installable ? t.updateInstall : t.updateOpenPage) : undefined} />)}
                  </div>
                </section>
              );
            })}
            {current.groups.some(g => g.items.some(i => i.advanced)) && (
              <section className="set-group set-adv">
                <button className="set-adv-toggle" aria-expanded={advOpen === current.id}
                  onClick={() => setAdvOpen(o => o === current.id ? null : current.id)}>
                  <span>{ts.ui.advanced}</span><Icon n={advOpen === current.id ? 'expand_less' : 'expand_more'} />
                </button>
                {advOpen === current.id && current.groups.map(g => {
                  const items = g.items.filter(i => i.advanced && enabled(i));
                  return items.length > 0 && (
                    <div className="set-adv-group" key={g.id}>
                      <span className="label">{ts.groups[g.id as keyof SettingsStrings['groups']]}</span>
                      <div className="set-card">
                        {items.map(s => <Row key={s.key} s={s} ts={ts} prefs={prefs} disabled={!enabled(s)} set={set} patch={patch} onAction={runAction} t={t} ssh={ssh} />)}
                      </div>
                    </div>
                  );
                })}
              </section>
            )}
          </>
        )}
      </main>

      <input ref={fileInput} type="file" accept="application/json,.json" hidden
        onChange={e => { importPrefs(e.target.files?.[0]); e.target.value = ''; }} />

      {confirmHello && createPortal(
        <div className="scrim" onClick={() => setConfirmHello(false)}>
          <div className="dialog" role="alertdialog" aria-label={t.helloTitle} onClick={e => e.stopPropagation()}>
            <h3><Icon n="fingerprint" />{t.helloTitle}</h3>
            <p className="dialog-body">{t.helloBody}</p>
            <p className="form-note"><Icon n="shield_lock" />{t.helloBoth}</p>
            <div className="row">
              <button className="btn text" onClick={() => setConfirmHello(false)}>{t.cancel}</button>
              <button className="btn filled" onClick={() => { onChange({ ...prefs, helloUnlock: true }); setConfirmHello(false); }}>{t.helloOk}</button>
            </div>
          </div>
        </div>
      , document.body)}
      {confirmReset && createPortal(
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
      , document.body)}
    </div>
  );
}

function Row({ s, ts, prefs, disabled, set, patch, onAction, t, ssh, button, quiet, flat }: {
  s: Setting; ts: SettingsStrings; prefs: Prefs; disabled: boolean; t: Strings; ssh: { path: string; reachable: boolean } | null;
  patch: (p: Partial<Prefs>) => void;
  /** no explanation in the row */
  quiet?: boolean;
  /** on a switch's own page: no indent for its sub-options */
  flat?: boolean;
  /** replaces the action button's text ("check now" → "install and restart") */
  button?: string;
  set: (key: PrefKey, value: Prefs[PrefKey]) => void; onAction: (key: string) => void;
}) {
  const label = ts.labels[s.key as keyof SettingsStrings['labels']];
  const hint = quiet ? undefined : ts.hints[s.key as keyof SettingsStrings['hints']];
  const id = 'set-' + s.key;
  const indent = !flat && 'dependsOn' in s && s.dependsOn;

  if (s.key === 'theme' || s.key === 'accent') {
    return (
      <div className="set-row set-wide">
        <div className="set-text"><span className="set-label">{label}</span>{hint && <span className="set-hint">{hint}</span>}</div>
        {s.key === 'theme' ? <ThemePicker ts={ts} prefs={prefs} set={set} /> : <SchemePicker ts={ts} prefs={prefs} set={set} />}
      </div>
    );
  }

  if (s.type === 'action') {
    return (
      <div className={'set-row' + (s.wip ? ' wip' : '')}>
        <div className="set-text"><span className="set-label">{s.key === 'updateNow' ? `${ts.ui.installedVersion} ${__APP_VERSION__}` : label}</span>{hint && <span className="set-hint">{hint}</span>}</div>
        {s.wip ? (
          <button className='wip-btn' disabled><Icon n={s.key === 'bwConnect' ? 'cloud' : 'dns'} />{label}<span className='pill'>{ts.ui.wip}</span></button>
        ) : (
          <button className={'btn ' + (s.key === 'reset' ? 'outlined' : 'tonal')} onClick={() => onAction(s.key)}>
            <Icon n={{ export: 'download', import: 'upload', reset: 'restart_alt', updateNow: 'system_update', layoutReset: 'view_column', ksGenerate: 'key', bwConnect: 'cloud', vwConnect: 'dns' }[s.key]} />{button ?? label}
          </button>
        )}
      </div>
    );
  }

  if (s.type === 'info') {
    const live = s.key === 'sshStatus' ? (ssh ? (ssh.reachable ? t.sshOk : t.sshDown) : '—') : s.key === 'sshAuthSockCurrent' ? ssh?.path ?? '—' : s.value;
    return (
      <div className={'set-row' + (indent ? ' indent' : '')}>
        <div className="set-text"><span className="set-label">{label}</span></div>
        <code className={'set-info' + (s.key === 'sshStatus' && ssh ? (ssh.reachable ? ' ok' : ' bad') : '')}>{live}</code>
      </div>
    );
  }

  const value = prefs[s.key];
  let control: React.ReactNode;
  if (s.type === 'toggle') {
    control = <input id={id} className="switch" type="checkbox" checked={value as boolean} disabled={disabled}
      onChange={e => set(s.key, e.target.checked)} />;
  } else if (s.type === 'number') {
    control = s.presets
      ? <Presets s={s} ts={ts} prefs={prefs} disabled={disabled} patch={patch} />
      : <NumberField id={id} s={s} value={value as number} disabled={disabled} unit={s.unit === 'd' ? ts.ui.days : s.unit}
        onCommit={n => set(s.key, n)} />;
  } else if (s.type === 'select' && s.options.length <= 4 && s.key !== 'lang') {
    control = <Choice options={s.options.map(o => [o, ts.options[o as keyof SettingsStrings['options']]])} value={value as string}
      disabled={disabled} onPick={o => set(s.key, o)} />;
  } else if (s.type === 'select') {
    control = (
      <Select variant="pill" value={value as string} disabled={disabled} onChange={v => set(s.key, v)} ariaLabel={ts.labels[s.key as keyof SettingsStrings['labels']] ?? s.key}
        options={s.options.map(o => ({ value: o, label: (s.key === 'lang' ? LANGS.find(l => l.id === o)?.name : ts.options[o as keyof SettingsStrings['options']]) ?? o }))} />
    );
  } else if (s.type === 'shortcut') {
    control = <ShortcutField id={id} value={value as string} disabled={disabled} ts={ts} onChange={v => set(s.key, v)} />;
  } else {
    control = (
      <span className="set-path">
        <input id={id} className="set-input" value={value as string} disabled={disabled}
          onChange={e => set(s.key, e.target.value)} spellCheck={false} />
        {s.type === 'path' && (
          // Note: browsers cannot return file paths; Tauri dialog plugin fills this in the desktop app
          <button className="icon-btn" disabled title={ts.ui.desktopHint} aria-label={ts.ui.browse}><Icon n="folder_open" /></button>
        )}
      </span>
    );
  }

  return (
    // time choices: value on the right, the list opens below (phone style)
    <div className={'set-row' + ((s.type === 'number' && s.presets) || (s.type === 'select' && s.options.length <= 4 && s.key !== 'lang') ? ' set-pick' : '') + (indent ? ' indent' : '') + (disabled ? ' off' : '')}>
      <label className="set-text" htmlFor={id}>
        <span className="set-label">{label}</span>
        {hint && <span className="set-hint">{hint}</span>}
        
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

// ---------------------------------------------------------------- look: preview cards

/** A tiny app window in the given colors: menu, list rows, accent button. */
function MiniApp({ c, oled }: { c: Colors; oled?: boolean }) {
  return (
    <span className="mini-app" aria-hidden style={{ '--mb': oled ? '#000' : c.bg, '--mf': c.fg, '--ma': c.acc } as React.CSSProperties}>
      <i className="mini-side"><b /><b /><b /></i>
      <i className="mini-list"><b /><b /><b /></i>
      <i className="mini-btn" />
    </span>
  );
}

type LookProps = { ts: SettingsStrings; prefs: Prefs; set: (key: PrefKey, value: Prefs[PrefKey]) => void };

function ThemePicker({ ts, prefs, set }: LookProps) {
  const dark = colorsOf(prefs.accent, 'dark', prefs), light = colorsOf(prefs.accent, 'light', prefs);
  const options = ['system', 'dark', 'light', 'oled'] as const;
  return (
    <div className="look-picks" role="radiogroup" aria-label={ts.labels.theme}>
      {options.map(o => (
        <button key={o} role="radio" aria-checked={prefs.theme === o} className={'look-pick' + (prefs.theme === o ? ' on' : '')} onClick={() => set('theme', o)}>
          {o === 'system'
            ? <span className="mini-split"><MiniApp c={light} /><MiniApp c={dark} oled={prefs.systemDark === 'oled'} /></span>
            : <MiniApp c={o === 'light' ? light : dark} oled={o === 'oled'} />}
          <span className="look-name">{ts.options[o]}</span>
        </button>
      ))}
    </div>
  );
}

function SchemePicker({ ts, prefs, set }: LookProps) {
  const theme = resolveTheme(prefs.theme, prefs.systemDark, prefersDark());
  const mode: Mode = theme === 'light' ? 'light' : 'dark';
  const ids = [...Object.keys(SCHEMES), 'custom'];
  return (
    <>
      <div className="look-picks schemes" role="radiogroup" aria-label={ts.labels.accent}>
        {ids.map(id => (
          <button key={id} role="radio" aria-checked={prefs.accent === id} className={'look-pick' + (prefs.accent === id ? ' on' : '')} onClick={() => set('accent', id)}>
            <MiniApp c={colorsOf(id, mode, prefs)} oled={theme === 'oled'} />
            <span className="look-name">{ts.options[id as keyof SettingsStrings['options']]}</span>
          </button>
        ))}
      </div>
      {prefs.accent === 'custom' && <CustomColorsEditor ts={ts} prefs={prefs} set={set} />}
    </>
  );
}

function CustomColorsEditor({ ts, prefs, set }: LookProps) {
  const ratio = (r: number) => r.toLocaleString(prefs.lang, { minimumFractionDigits: 1, maximumFractionDigits: 1 });
  const modes: [Mode, string, PrefKey, PrefKey, PrefKey][] = [
    ['dark', ts.ui.ownDark, 'customDarkBg', 'customDarkFg', 'customDarkAcc'],
    ['light', ts.ui.ownLight, 'customLightBg', 'customLightFg', 'customLightAcc'],
  ];
  return (
    <div className="own-colors">
      {modes.map(([mode, title, bg, fg, acc]) => {
        const c = colorsOf('custom', mode, prefs);
        const text = contrast(c.fg, c.bg), accent = contrast(c.acc, c.bg);
        return (
          <fieldset key={mode} className="own-mode">
            <legend>{title}</legend>
            {([[bg, ts.ui.bg], [fg, ts.ui.fg], [acc, ts.ui.acc]] as const).map(([key, name]) => (
              <label key={key} className="own-color">
                <input type="color" value={prefs[key] as string} onChange={e => set(key, e.target.value)} />
                <span>{name}</span>
                <code>{prefs[key] as string}</code>
              </label>
            ))}
            {text < 4.5 && <p className="own-warn">{ts.ui.contrastText.replace('{r}', ratio(text))}</p>}
            {accent < 3 && <p className="own-warn">{ts.ui.contrastAcc.replace('{r}', ratio(accent))}</p>}
          </fieldset>
        );
      })}
    </div>
  );
}

/** a time or size as people say it, in the UI language: 300 s → "5 Minuten" */
function amount(n: number, unit: string, lang: string) {
  const fmt = (v: number, u: string) => new Intl.NumberFormat(lang, { style: 'unit', unit: u, unitDisplay: 'long', maximumFractionDigits: 1 }).format(v);
  if (unit === 's') return n < 60 ? fmt(n, 'second') : n < 3600 ? fmt(Math.round(n / 60), 'minute') : fmt(n / 3600, 'hour');
  if (unit === 'min') return n < 60 ? fmt(n, 'minute') : fmt(n / 60, 'hour');
  if (unit === 'd') return fmt(n, 'day');
  if (unit === '%') return `${n} %`;
  return unit ? `${n} ${unit}` : String(n);
}

/** Like a phone's settings: the row shows the current value; a click opens the choices below
 *  with a check mark. "Never" switches the feature off; "Custom" takes any number. */
function Presets({ s, ts, prefs, disabled, patch }: {
  s: Extract<Setting, { type: 'number' }>; ts: SettingsStrings; prefs: Prefs; disabled: boolean; patch: (p: Partial<Prefs>) => void;
}) {
  const value = prefs[s.key] as number;
  const presets = s.presets ?? [];
  const never = s.never;
  const isNever = typeof never === 'string' ? !prefs[never] : never !== undefined && value === never;
  const custom = !isNever && !presets.includes(value);
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState(false);
  const say = (n: number) => amount(n, s.unit, prefs.lang);
  const choose = (n: number) => { patch({ [s.key]: n, ...(typeof never === 'string' ? { [never]: true } : {}) } as Partial<Prefs>); setOpen(false); setEditing(false); };
  const off = () => { patch((typeof never === 'string' ? { [never]: false } : { [s.key]: never }) as Partial<Prefs>); setOpen(false); };
  const item = (label: string, on: boolean, act: () => void) => (
    <button key={label} role="menuitemradio" aria-checked={on} className={on ? 'on' : ''} onClick={act}>
      <span>{label}</span>{on && <Icon n="check" />}
    </button>
  );
  return (
    <>
      <button className="pick-value" disabled={disabled} aria-expanded={open} onClick={() => setOpen(o => !o)}>
        {isNever ? ts.ui.never : say(value)}<Icon n={open ? 'expand_less' : 'expand_more'} />
      </button>
      {open && (
        <div className="pick-list" role="menu">
          {presets.map(n => item(say(n), !isNever && value === n, () => choose(n)))}
          {never !== undefined && item(ts.ui.never, isNever, off)}
          {item(custom ? `${ts.ui.custom}: ${say(value)}` : ts.ui.custom, custom, () => setEditing(e => !e))}
          {editing && (
            <span className="pick-custom">
              <NumberField id={'set-' + s.key} s={s} value={value} disabled={disabled} unit={s.unit === 'd' ? ts.ui.days : s.unit} onCommit={choose} />
            </span>
          )}
        </div>
      )}
    </>
  );
}

/** Short lists (2–4 options) work like the time choices: value on the right, menu below. */
function Choice({ options, value, disabled, onPick }: { options: [string, string][]; value: string; disabled: boolean; onPick: (o: string) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button className="pick-value" disabled={disabled} aria-expanded={open} onClick={() => setOpen(o => !o)}>
        {options.find(([o]) => o === value)?.[1] ?? value}<Icon n={open ? 'expand_less' : 'expand_more'} />
      </button>
      {open && (
        <div className="pick-list" role="menu">
          {options.map(([o, label]) => (
            <button key={o} role="menuitemradio" aria-checked={o === value} className={o === value ? 'on' : ''}
              onClick={() => { onPick(o); setOpen(false); }}><span>{label}</span>{o === value && <Icon n="check" />}</button>
          ))}
        </div>
      )}
    </>
  );
}

/** A switch with sub-options: summary on the right; a click turns the arrow down and the
 *  card grows with the switch and its options. */
function SubRow({ label, summary, open, onToggle, children }: {
  label: string; summary: string; open: boolean; onToggle: () => void; children: React.ReactNode;
}) {
  return (
    <div className={'set-sub' + (open ? ' open' : '')}>
      <button className="set-row set-nav" aria-expanded={open} onClick={onToggle}>
        <span className="set-text"><span className="set-label">{label}</span>{!open && <span className="set-hint">{summary}</span>}</span>
        <Icon n="chevron_right" />
      </button>
      {open && <div className="set-sub-body">{children}</div>}
    </div>
  );
}
