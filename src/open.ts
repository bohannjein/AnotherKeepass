import { openUrl } from '@tauri-apps/plugin-opener';

// Desktop: hand URLs to the system browser. Browser preview: new tab.
const inTauri = '__TAURI_INTERNALS__' in window;
export const openExternal = (url: string) =>
  inTauri ? openUrl(url) : window.open(url, '_blank', 'noopener');
