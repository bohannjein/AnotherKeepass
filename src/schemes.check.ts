// node src/schemes.check.ts
// Text on the background and the accent on the background must be readable (WCAG AA).
import { CUSTOM_DEFAULTS, SCHEMES, contrast, customOf } from './schemes.ts';

const modes = ['dark', 'light'] as const;
const bad: string[] = [];
const check = (name: string, mode: string, c: { bg: string; fg: string; acc: string }) => {
  const text = contrast(c.fg, c.bg);
  const accent = contrast(c.acc, c.bg);
  if (text < 4.5) bad.push(`${name} ${mode}: text ${text.toFixed(2)} < 4.5`);
  if (accent < 3) bad.push(`${name} ${mode}: accent ${accent.toFixed(2)} < 3 (large text and controls)`);
};
for (const [name, s] of Object.entries(SCHEMES)) for (const m of modes) check(name, m, s[m]);
for (const m of modes) check('custom (default)', m, customOf(CUSTOM_DEFAULTS, m));

if (contrast('#000000', '#ffffff') < 20.9) bad.push('contrast(): black on white should be 21');
if (bad.length) throw new Error('contrast too low:\n' + bad.join('\n'));
console.log('schemes ok');
