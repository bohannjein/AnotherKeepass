// Self-check for the password generators. Run: node src/generator.check.ts
import { generate, randomBits, strengthOf } from './generator.ts';
import { passphrase, phraseBits } from './passphrase.ts';

for (let i = 0; i < 200; i++) {
  const p = passphrase({ words: 5, capitalize: true, numbers: true, separator: '-' });
  const parts = p.split('-').filter(Boolean);
  if (parts.length < 5) throw new Error('too few words: ' + p);
  if (!/^[A-Z]/.test(p) || !/\d$/.test(p)) throw new Error('format: ' + p);
  const r = generate({ length: 20, upper: true, digits: true, symbols: true });
  if (r.length !== 20 || !/[A-Z]/.test(r) || !/\d/.test(r) || !/[^A-Za-z0-9]/.test(r)) throw new Error('random: ' + r);
}
if (strengthOf(phraseBits({ words: 5, capitalize: true, numbers: true, separator: '-' })) !== 'strong') throw new Error('5 words should be strong');
if (strengthOf(phraseBits({ words: 3, capitalize: false, numbers: false, separator: '-' })) !== 'weak') throw new Error('3 words should be weak');
if (strengthOf(randomBits({ length: 8, upper: false, digits: false, symbols: false })) !== 'weak') throw new Error('8 lowercase should be weak');
console.log('generator ok');
