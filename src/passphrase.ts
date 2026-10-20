import { long as WORDS } from '@wordlist/english-eff/long';
import { randIndex } from './generator.ts';

// ---------- memorable passphrases (EFF long list, 7776 words ≈ 12.9 bits each) ----------

export type PhraseOpts = { words: number; capitalize: boolean; numbers: boolean; separator: string };

/** e.g. "Galley8-Magician5-Padding3" — one digit after each word when `numbers` is on. */
export function passphrase(o: PhraseOpts): string {
  return Array.from({ length: o.words }, () => {
    const w = WORDS[randIndex(WORDS.length)];
    return (o.capitalize ? w[0].toUpperCase() + w.slice(1) : w) + (o.numbers ? randIndex(10) : '');
  }).join(o.separator);
}

export function phraseBits(o: PhraseOpts) {
  return o.words * (Math.log2(WORDS.length) + (o.numbers ? Math.log2(10) : 0));
}
