import { invoke } from '@tauri-apps/api/core';
import { openUrl } from '@tauri-apps/plugin-opener';

// Desktop: hand URLs to the system browser. Browser preview: new tab.
const inTauri = '__TAURI_INTERNALS__' in window;
// set from the settings ("minimize window when opening a URL")
export const openOptions = { minimize: false };
export const openExternal = async (url: string) => {
  if (!inTauri) { window.open(url, '_blank', 'noopener'); return; }
  await openUrl(url);
  if (openOptions.minimize) await invoke('window_minimize');
};
