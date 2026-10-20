const SETS = {
  lower: 'abcdefghijkmnopqrstuvwxyz',
  upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
  digits: '23456789',
  symbols: '!#$%&*+-=?@_.',
};

export type GenOpts = { length: number; upper: boolean; digits: boolean; symbols: boolean };

// Unbiased random index via rejection sampling (plain `% n` skews toward low chars).
export function randIndex(n: number): number {
  const limit = Math.floor(0x100000000 / n) * n;
  const buf = new Uint32Array(1);
  do crypto.getRandomValues(buf); while (buf[0] >= limit);
  return buf[0] % n;
}

export function generate(o: GenOpts): string {
  const sets = [SETS.lower];
  if (o.upper) sets.push(SETS.upper);
  if (o.digits) sets.push(SETS.digits);
  if (o.symbols) sets.push(SETS.symbols);
  const all = sets.join('');
  // one char from each enabled set, rest from the pool, then shuffle
  const chars = sets.map(s => s[randIndex(s.length)]);
  while (chars.length < o.length) chars.push(all[randIndex(all.length)]);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randIndex(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

// ---------- strength = entropy of the generator settings (not of the string) ----------
export function randomBits(o: GenOpts) {
  const pool = SETS.lower.length + (o.upper ? SETS.upper.length : 0) + (o.digits ? SETS.digits.length : 0) + (o.symbols ? SETS.symbols.length : 0);
  return o.length * Math.log2(pool);
}
export type Strength = 'weak' | 'medium' | 'strong';
export const strengthOf = (bits: number): Strength => bits < 50 ? 'weak' : bits < 75 ? 'medium' : 'strong';

// ---------- session history (memory only, cleared on lock) ----------
export const history: { value: string; at: number }[] = [];
export function remember(value: string) {
  if (history[0]?.value === value) return;
  history.unshift({ value, at: Date.now() });
  history.length = Math.min(history.length, 20);
}
export const clearHistory = () => { history.length = 0; };
