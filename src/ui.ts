// Small helpers and constants shared by the list, the detail pane and dialogs.
import { iconUrl, type ItemType, type Item } from './model';
import { type Strings } from './i18n';

/** Display name of a vault path: file name, or "email · server" for a Vaultwarden account. */
export const fileName = (path: string) => {
  const bw = path.match(/^bw:(?:https?:\/\/)?([^#/]+)[^#]*#(.+)$/);
  return bw ? `${bw[2]} · ${bw[1]}` : path.replace(/^demo:/, '').split(/[\\/]/).pop() ?? path;
};
export const isRemote = (path: string) => path.startsWith('bw:');

export type Issue = 'breached' | 'weak' | 'reused' | 'old' | 'expired';
export const ISSUES: Issue[] = ['breached', 'weak', 'reused', 'old', 'expired'];
export const ISSUE_ICON: Record<Issue, string> = {
  breached: 'gpp_maybe', weak: 'key_off', reused: 'repeat', old: 'hourglass_bottom', expired: 'event_busy',
};
export const issueName = (t: Strings, k: Issue) =>
  ({ breached: t.hBreached, weak: t.hWeak, reused: t.hReused, old: t.hOld, expired: t.hExpired })[k];

export const IMAGE = /\.(png|jpe?g|gif|webp|bmp|svg|ico)$/i;
const TEXT = /\.(txt|md|log|json|xml|ya?ml|csv|ini|conf|cfg|pem|pub|key|crt|cer|asc|sh|ps1|toml)$/i;
/** Attachments the in-app preview can show. */
export const previewable = (name: string) => IMAGE.test(name) || TEXT.test(name);

export type Theme = 'dark' | 'light';

export const TYPE_ICON: Record<ItemType, string> = {
  login: 'person', card: 'credit_card', note: 'sticky_note_2', pin: 'pin', identity: 'badge', other: 'category',
};
export const today = () => new Date().toISOString().slice(0, 10);

export const isExpired = (i: Item) => !!i.expires && i.expires < today();

/** Any image the webview can decode → 64×64 PNG (base64), what KeePass clients expect. */
export function toPng(b64: string): Promise<string | null> {
  return new Promise(resolve => {
    const img = new Image();
    img.onload = () => {
      const c = document.createElement('canvas');
      c.width = c.height = 64;
      const ctx = c.getContext('2d');
      if (!ctx || !img.width) return resolve(null);
      ctx.imageSmoothingQuality = 'high';
      ctx.drawImage(img, 0, 0, 64, 64);
      resolve(c.toDataURL('image/png').split(',')[1] ?? null);
    };
    img.onerror = () => resolve(null);
    img.src = iconUrl(b64);
  });
}
