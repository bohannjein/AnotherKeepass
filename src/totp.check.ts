// Self-check against RFC 6238 Appendix B (SHA-1). Run: node src/totp.check.ts
import { totp } from './totp.ts';
const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // "12345678901234567890"
const cases: [number, string][] = [[59, '94287082'], [1111111109, '07081804'], [2000000000, '69279037']];
for (const [t, want] of cases) {
  const got = await totp(secret, t * 1000, 8);
  if (got !== want) throw new Error(`t=${t}: got ${got}, want ${want}`);
}
const uri = await totp(`otpauth://totp/x?secret=${secret}`, 59000, 8);
if (uri !== '94287082') throw new Error('otpauth uri parse failed');
console.log('totp ok');
