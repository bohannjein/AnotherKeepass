// node src/i18n.check.ts
// All four languages have the same keys, no empty texts, the same {placeholders} as English,
// and nothing is left in English by mistake.
import { strings } from './i18n.ts';
import { settingsStrings } from './i18n-settings.ts';

// words and names that are the same in every language
const SAME = /^(AnotherKeepass|KeePass|KeePassXC|KDBX|TOTP|YubiKey|SSH|Argon2|CSV|JSON|Windows Hello|Bitwarden|1Password|Proton Pass|Vaultwarden|OLED|Auto-Type|URL|PIN|Wi-Fi|OK|Nord|Gruvbox|Solarized|Dracula|Tokyo Night|Everforest|Rosé Pine|Terracotta|Slot|Backup|Note|Notes?|Total|Hello|Email|E-mail|Version|Standard|Pin|Logo|Icon|Menu|Tags?|Offline|Online|Server|Proxy|Passkeys?|Format|Debug|Linux|macOS|Beta|Original|Document|Admin|Local|Passphrase|Fingerprint|Login|Web|Mix|Test|Demo|Sync|Gap|Max|Min|Google Chrome|Mozilla Firefox|Microsoft Edge|PuTTY Pageant)\b.*$/i;

const errors: string[] = [];
const langs = ['de', 'fr', 'es'] as const;

type Tree = { [k: string]: string | string[] | Tree };
const flat = (o: Tree, prefix = ''): Map<string, string> => {
  const out = new Map<string, string>();
  for (const [k, v] of Object.entries(o)) {
    const key = prefix + k;
    if (typeof v === 'string') out.set(key, v);
    else if (Array.isArray(v)) v.forEach((x, i) => out.set(`${key}[${i}]`, String(x)));
    else for (const [a, b] of flat(v, key + '.')) out.set(a, b);
  }
  return out;
};
const holes = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map(m => m[1]).sort().join(',');

const compare = (label: string, all: Record<string, Tree>) => {
  const en = flat(all.en);
  for (const l of langs) {
    const other = flat(all[l]);
    for (const k of en.keys()) if (!other.has(k)) errors.push(`${label} ${l}: missing ${k}`);
    for (const k of other.keys()) if (!en.has(k)) errors.push(`${label} ${l}: extra key ${k}`);
    for (const [k, v] of other) {
      const e = en.get(k);
      if (e === undefined) continue;
      if (!v.trim() && e.trim()) errors.push(`${label} ${l}: empty ${k}`);
      if (holes(v) !== holes(e)) errors.push(`${label} ${l}: placeholders of ${k} differ ({${holes(v)}} vs {${holes(e)}})`);
      // identical to English: fine for names and very short strings, suspicious otherwise
      if (v === e && e.length > 12 && /\s/.test(e) && !SAME.test(e)) errors.push(`${label} ${l}: still English? ${k} = "${e}"`);
    }
  }
};
compare('ui', strings as unknown as Record<string, Tree>);
compare('settings', settingsStrings as unknown as Record<string, Tree>);

if (errors.length) {
  console.error(errors.slice(0, 80).join('\n') + (errors.length > 80 ? `\n… and ${errors.length - 80} more` : ''));
  throw new Error(`${errors.length} translation problems`);
}
console.log('i18n ok');
