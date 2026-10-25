// Small helpers and constants shared by the list, the detail pane and dialogs.
import { iconUrl, type ItemType, type Item } from './model';

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
