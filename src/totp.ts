// RFC 6238 TOTP (SHA-1, 30 s, 6 digits) via WebCrypto. Accepts a base32 secret
// or an otpauth:// URI (KeePassXC stores the latter in the `otp` field).

function base32(input: string): Uint8Array<ArrayBuffer> {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = input.toUpperCase().replace(/[\s=-]/g, '');
  const out: number[] = [];
  let bits = 0, acc = 0;
  for (const c of clean) {
    const v = alphabet.indexOf(c);
    if (v < 0) throw new Error('invalid base32');
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) { out.push((acc >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(out);
}

export function secretOf(value: string): string {
  if (!value.startsWith('otpauth://')) return value;
  return new URL(value).searchParams.get('secret') ?? '';
}

export async function totp(value: string, now = Date.now(), digits = 6, period = 30): Promise<string> {
  const key = await crypto.subtle.importKey('raw', base32(secretOf(value)), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const counter = new DataView(new ArrayBuffer(8));
  counter.setBigUint64(0, BigInt(Math.floor(now / 1000 / period)));
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, counter.buffer));
  const o = h[h.length - 1] & 0x0f;
  const bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}
