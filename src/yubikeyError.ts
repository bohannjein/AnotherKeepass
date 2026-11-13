import type { Strings } from './i18n';

/** What a YubiKey error from Rust means for the person at the keyboard. */
export const yubikeyError = (t: Strings, e: unknown) => {
  const s = String(e);
  if (/Multiple|Ambiguous/i.test(s)) return t.ykMultiple;
  return /No challenge|NoKeys|no.*key/i.test(s) ? t.yubikeyMissing : t.yubikeyFailed;
};
