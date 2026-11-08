// First start: pick language, theme and color scheme.
import { useState, useEffect } from 'react';
import { type Lang, strings, LANGS } from './i18n';
import { settingsStrings } from './i18n-settings';
import { Icon } from './Icon';
import { type Theme } from './ui';
import { SCHEMES } from './schemes';

const THEMES: { id: Theme; icon: string }[] = [
  { id: 'dark', icon: 'dark_mode' }, { id: 'light', icon: 'light_mode' }, { id: 'oled', icon: 'contrast' },
];

export function Setup({ onDone }: { onDone: (s: { lang: Lang; theme: Theme; accent: string }) => void }) {
  const [step, setStep] = useState(0);
  const [lang, setLang] = useState<Lang>('en');
  const [theme, setTheme] = useState<Theme>('dark');
  const [accent, setAccent] = useState('terracotta');
  const t = strings[lang];
  const ts = settingsStrings[lang];

  // live preview of the choices while in setup
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.dataset.accent = accent;
    document.documentElement.lang = lang;
  }, [theme, accent, lang]);

  const mode = theme === 'light' ? 'light' : 'dark';
  return (
    <div className="center">
      <div className="sheet">
        <div className="steps"><i className="on" /><i className={step === 1 ? 'on' : ''} /></div>
        <div className="logo"><Icon n="encrypted" fill /></div>
        <h1>{t.welcome} <span>✦</span></h1>
        <p>{t.setupIntro}</p>

        {step === 0 ? (
          <>
            <span className="label">{t.language}</span>
            <div className="choices">
              {LANGS.map(l => (
                <button key={l.id} className={'choice' + (lang === l.id ? ' on' : '')} onClick={() => setLang(l.id)}>
                  {l.name}{lang === l.id && <Icon n="check_circle" fill />}
                </button>
              ))}
            </div>
            <div className="row"><span /><button className="btn filled" onClick={() => setStep(1)}>{t.continue}<Icon n="arrow_forward" /></button></div>
          </>
        ) : (
          <>
            <span className="label">{t.appearance}</span>
            <div className="choices three">
              {THEMES.map(({ id, icon }) => (
                <button key={id} className={'choice theme-tile' + (theme === id ? ' on' : '')} onClick={() => setTheme(id)}>
                  <span className={'preview ' + id}><i /><i /></span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Icon n={icon} />{ts.options[id]}
                  </span>
                </button>
              ))}
            </div>
            <span className="label">{ts.labels.accent}</span>
            <div className="scheme-picks" role="radiogroup" aria-label={ts.labels.accent}>
              {Object.entries(SCHEMES).map(([id, c]) => {
                const name = ts.options[id as keyof typeof ts.options];
                const { bg, acc } = c[mode];
                return (
                  <button key={id} role="radio" aria-checked={accent === id} title={name} aria-label={name}
                    className={'scheme-pick' + (accent === id ? ' on' : '')} onClick={() => setAccent(id)}
                    style={{ background: `linear-gradient(135deg, ${theme === 'oled' ? '#000' : bg} 50%, ${acc} 50%)` }} />
                );
              })}
            </div>
            <p className="scheme-name">{ts.options[accent as keyof typeof ts.options]}</p>
            <div className="row">
              <button className="btn text" onClick={() => setStep(0)}><Icon n="arrow_back" />{t.back}</button>
              <button className="btn filled" onClick={() => onDone({ lang, theme, accent })}>{t.finish}<Icon n="arrow_forward" /></button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
