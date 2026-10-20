// Password generator dialog (memorable passphrases / random). Loaded on first use:
// it pulls in the 7776-word EFF list.
import { useState } from 'react';
import { createPortal } from 'react-dom';
import { generate, history, randomBits, remember, strengthOf, type GenOpts, type Strength } from './generator';
import { passphrase, phraseBits, type PhraseOpts } from './passphrase';
import { colorize } from './colorize';
import type { Strings } from './i18n';
import { Icon } from './Icon';

type GenState = { mode: 'memorable' | 'random'; phrase: PhraseOpts; random: GenOpts };
// last used generator settings, kept for the session
let lastGen: GenState = {
  mode: 'memorable',
  phrase: { words: 5, capitalize: true, numbers: true, separator: '-' },
  random: { length: 20, upper: true, digits: true, symbols: true },
};
const SEPARATORS = ['-', '.', '_', ',', ' '];
const STRENGTH_ICON: Record<Strength, string> = { weak: 'gpp_bad', medium: 'gpp_maybe', strong: 'verified_user' };

/** Password generator dialog. With `onUse` it fills a field (entry editing), otherwise it copies. */
export default function Generator({ t, onClose, onCopy, onUse }: {
  t: Strings; onClose: () => void; onCopy: (text: string, what: string) => void; onUse?: (pw: string) => void;
}) {
  const [g, setG] = useState<GenState>(lastGen);
  const make = (s: GenState) => s.mode === 'memorable' ? passphrase(s.phrase) : generate(s.random);
  const [pw, setPw] = useState(() => make(g));
  const [showHistory, setShowHistory] = useState(false);
  const update = (s: GenState) => { lastGen = s; setG(s); setPw(make(s)); };
  const bits = g.mode === 'memorable' ? phraseBits(g.phrase) : randomBits(g.random);
  const strength = strengthOf(bits);
  const strengthLabel = { weak: t.strengthWeak, medium: t.strengthMedium, strong: t.strengthStrong }[strength];
  const use = () => { remember(pw); if (onUse) { onUse(pw); onClose(); } else onCopy(pw, t.password); };
  const p = g.phrase, r = g.random;

  // portal: the detail pane is a CSS container, which would trap a fixed dialog inside it
  return createPortal(
    <div className="scrim" onClick={onClose}>
      <div className="dialog gen-dialog" role="dialog" aria-label={t.generator} onClick={e => e.stopPropagation()}>
        <div className="gen-top">
          <button className="icon-btn" onClick={onClose} aria-label={t.close}><Icon n="close" /></button>
          <span className="gen-title">{t.generator}</span>
          <button className="icon-btn tonal" onClick={() => setPw(make(g))} title={t.regenerate} aria-label={t.regenerate}><Icon n="refresh" /></button>
          <button className="btn filled" onClick={use}>
            <Icon n={onUse ? 'input' : 'content_copy'} />{onUse ? t.genUse : t.copy}
          </button>
        </div>

        <output className="gen-output" aria-live="polite">
          {g.mode === 'memorable' && p.separator
            // allow line breaks only after a separator, never inside a word
            ? pw.split(p.separator).map((w, i) => <span key={i}>{i > 0 && <><span className="pw-s">{p.separator}</span><wbr /></>}{colorize(w)}</span>)
            : colorize(pw)}
        </output>
        <div className={'strength ' + strength} title={`≈ ${Math.round(bits)} bit`}>
          <Icon n={STRENGTH_ICON[strength]} fill />{strengthLabel}
          <span className="meter"><i style={{ transform: `scaleX(${Math.min(1, bits / 120)})` }} /></span>
        </div>

        <div className="gen-opts">
          <label className="opt">{t.genType}
            <select className="set-select" value={g.mode} onChange={e => update({ ...g, mode: e.target.value as GenState['mode'] })}>
              <option value="memorable">{t.genMemorable}</option>
              <option value="random">{t.genRandom}</option>
            </select>
          </label>
          {g.mode === 'memorable' ? (
            <>
              <label className="opt">{p.words} {t.genWords}
                <input type="range" min={3} max={10} value={p.words} onChange={e => update({ ...g, phrase: { ...p, words: +e.target.value } })} />
              </label>
              <label className="opt">{t.genCapitalize}
                <input className="switch" type="checkbox" checked={p.capitalize} onChange={e => update({ ...g, phrase: { ...p, capitalize: e.target.checked } })} />
              </label>
              <label className="opt">{t.genNumbers}
                <input className="switch" type="checkbox" checked={p.numbers} onChange={e => update({ ...g, phrase: { ...p, numbers: e.target.checked } })} />
              </label>
              <div className="opt">{t.genSeparator}
                <span className="sep-chips">
                  {SEPARATORS.map(s => (
                    <button key={s} className={'chip' + (p.separator === s ? ' on' : '')} title={s === ' ' ? t.genSpace : s}
                      onClick={() => update({ ...g, phrase: { ...p, separator: s } })}>{s === ' ' ? '␣' : s}</button>
                  ))}
                </span>
              </div>
            </>
          ) : (
            <>
              <label className="opt">{t.length}: {r.length}
                <input type="range" min={8} max={64} value={r.length} onChange={e => update({ ...g, random: { ...r, length: +e.target.value } })} />
              </label>
              <label className="opt">{t.uppercase}
                <input className="switch" type="checkbox" checked={r.upper} onChange={e => update({ ...g, random: { ...r, upper: e.target.checked } })} />
              </label>
              <label className="opt">{t.digits}
                <input className="switch" type="checkbox" checked={r.digits} onChange={e => update({ ...g, random: { ...r, digits: e.target.checked } })} />
              </label>
              <label className="opt">{t.symbols}
                <input className="switch" type="checkbox" checked={r.symbols} onChange={e => update({ ...g, random: { ...r, symbols: e.target.checked } })} />
              </label>
            </>
          )}
        </div>

        <button className="gen-history-toggle" onClick={() => setShowHistory(h => !h)} aria-expanded={showHistory}>
          {t.genHistory}<Icon n={showHistory ? 'expand_less' : 'chevron_right'} />
        </button>
        {showHistory && (
          <div className="gen-history">
            {history.length === 0 && <span className="label">{t.genHistoryEmpty}</span>}
            {history.map(h => (
              <button key={h.at + h.value} className="gen-history-row" onClick={() => onCopy(h.value, t.password)} title={t.copy}>
                <span className="mono">{h.value}</span>
                <small>{new Date(h.at).toLocaleTimeString(document.documentElement.lang, { hour: '2-digit', minute: '2-digit' })}</small>
                <Icon n="content_copy" />
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
    , document.body);
}
