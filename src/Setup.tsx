// First start: pick language and theme.
import { useState, useEffect } from 'react';
import { type Lang, strings, LANGS } from './i18n';
import { Icon } from './Icon';
import { type Theme } from './ui';

export function Setup({ onDone }: { onDone: (s: { lang: Lang; theme: Theme }) => void }) {
  const [step, setStep] = useState(0);
  const [lang, setLang] = useState<Lang>('en');
  const [theme, setTheme] = useState<Theme>('dark');
  const t = strings[lang];

  // live preview of the choices while in setup
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.lang = lang;
  }, [theme, lang]);

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
            <div className="choices">
              {(['dark', 'light'] as const).map(th => (
                <button key={th} className={'choice theme-tile' + (theme === th ? ' on' : '')} onClick={() => setTheme(th)}>
                  <span className={'preview ' + th}><i /><i /></span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Icon n={th === 'dark' ? 'dark_mode' : 'light_mode'} />{t[th]}
                  </span>
                </button>
              ))}
            </div>
            <div className="row">
              <button className="btn text" onClick={() => setStep(0)}><Icon n="arrow_back" />{t.back}</button>
              <button className="btn filled" onClick={() => onDone({ lang, theme })}>{t.finish}<Icon n="arrow_forward" /></button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
