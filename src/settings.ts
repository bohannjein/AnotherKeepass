// Application settings: one schema drives defaults, the settings page and import validation.
// Defaults follow KeePassXC. `planned: true` = stored, but the feature is not built yet (hidden unless "show planned").
import type { Lang } from './i18n';

export const DEFAULTS = {
  lang: 'en' as Lang,
  showPlanned: false,
  theme: 'dark' as 'dark' | 'light',

  // General · startup
  singleInstance: true,
  autostart: false,
  startMinimized: false,
  minimizeAfterUnlock: false,
  rememberRecent: true,
  recentCount: 5,
  reopenLast: true,
  rememberKeyfiles: true,
  updateCheck: false,
  updateBeta: false,
  showExpiring: true,
  expiryDays: 7,
  // General · files
  autoReload: true,
  backupBeforeSave: false,
  backupPath: '{DB_FILENAME}.old.kdbx',
  // General · entries
  confirmTrash: true,
  generateForNew: true,
  copyOnDoubleClick: false,
  urlDoubleClick: 'open',
  minimizeOnUrl: false,
  onCopy: 'none',
  faviconTimeout: 10,
  // General · interface
  fontSize: 100,
  colorizePasswords: true,
  monospaceNotes: false,
  trayIcon: true,
  trayStyle: 'colorful',
  hideToTray: false,

  // Auto-Type
  atMatchTitle: true,
  atMatchUrl: true,
  atAlwaysAsk: true,
  atHideExpired: false,
  atRelock: false,
  atShortcut: '',
  atRemember: 10,
  atStartDelay: 500,
  atCharDelay: 25,

  // Security
  clipboardClear: true,
  clipboardSeconds: 10,
  autoLock: false,
  autoLockSeconds: 240,
  clearSearch: true,
  clearSearchMinutes: 5,
  quickUnlock: true,
  lockOnSession: true,
  lockOnUserSwitch: true,
  lockOnMinimize: false,
  passwordPlaceholder: false,
  hideInEdit: true,
  hidePwPreview: true,
  hideTotpPreview: false,
  hideNotesPreview: false,
  ddgFavicons: false,

  // Browser integration (KeePassXC-Browser protocol)
  browserEnabled: false,
  bChrome: false,
  bFirefox: false,
  bChromium: false,
  bEdge: false,
  bBrave: false,
  bVivaldi: false,
  bTor: false,
  bUnlock: true,
  bMatchScheme: true,
  bBestMatch: false,
  bAllowExpired: false,
  bSearchAll: false,
  bNoAccessConfirm: false,
  bUpdateNoConfirm: false,
  bSkipBasicAuth: false,
  bKph: false,
  bLocalhostPasskeys: false,
  bUpdateManifests: true,
  bCustomProxy: false,
  bProxyPath: '',
  bCustomBrowser: false,
  bCustomType: 'firefox',
  bCustomPath: '',

  // SSH agent
  sshEnabled: false,
  sshAgent: 'openssh',
  sshAuthSock: '',
  skProvider: '',

  // KeeShare
  ksImport: false,
  ksExport: false,
  ksQuiet: false,
  ksSigner: '',
};

export type Prefs = typeof DEFAULTS;
export type PrefKey = keyof Prefs;

export type Setting =
  | { key: PrefKey; type: 'toggle' | 'text' | 'path' | 'shortcut'; planned?: boolean; dependsOn?: PrefKey; platform?: Platform }
  | { key: PrefKey; type: 'number'; min: number; max: number; unit: 's' | 'ms' | 'min' | 'd' | '%' | ''; step?: number; planned?: boolean; dependsOn?: PrefKey; platform?: Platform }
  | { key: PrefKey; type: 'select'; options: string[]; planned?: boolean; dependsOn?: PrefKey; platform?: Platform }
  | { key: 'sshStatus' | 'sshAuthSockCurrent' | 'skProviderCurrent' | 'ksFingerprint'; type: 'info'; value: string; platform?: Platform }
  | { key: 'reset' | 'import' | 'export' | 'updateNow' | 'ksGenerate' | 'bwConnect' | 'vwConnect'; type: 'action'; planned?: boolean; wip?: boolean };

export type Platform = 'windows' | 'linux-mac';
export interface Group { id: string; items: Setting[] }
export interface Section { id: string; icon: string; groups: Group[] }


export const SECTIONS: Section[] = [
  {
    id: 'general', icon: 'tune', groups: [
      {
        id: 'startup', items: [
          { key: 'singleInstance', type: 'toggle' },
          { key: 'autostart', type: 'toggle' },
          { key: 'startMinimized', type: 'toggle' },
          { key: 'minimizeAfterUnlock', type: 'toggle' },
          { key: 'rememberRecent', type: 'toggle' },
          { key: 'recentCount', type: 'number', min: 1, max: 25, unit: '', dependsOn: 'rememberRecent' },
          { key: 'reopenLast', type: 'toggle', dependsOn: 'rememberRecent' },
          { key: 'rememberKeyfiles', type: 'toggle', dependsOn: 'rememberRecent' },
          { key: 'updateCheck', type: 'toggle' },
          { key: 'updateBeta', type: 'toggle', dependsOn: 'updateCheck' },
          { key: 'updateNow', type: 'action' },
          { key: 'showExpiring', type: 'toggle' },
          { key: 'expiryDays', type: 'number', min: 0, max: 90, unit: 'd', dependsOn: 'showExpiring' },
        ],
      },
      {
        id: 'files', items: [
          { key: 'autoReload', type: 'toggle' },
          { key: 'backupBeforeSave', type: 'toggle' },
          { key: 'backupPath', type: 'path', dependsOn: 'backupBeforeSave' },
        ],
      },
      {
        id: 'entries', items: [
          { key: 'confirmTrash', type: 'toggle' },
          { key: 'generateForNew', type: 'toggle' },
          { key: 'copyOnDoubleClick', type: 'toggle' },
          { key: 'urlDoubleClick', type: 'select', options: ['open', 'copy', 'edit'] },
          { key: 'minimizeOnUrl', type: 'toggle' },
          { key: 'onCopy', type: 'select', options: ['none', 'minimize', 'background'] },
          { key: 'faviconTimeout', type: 'number', min: 1, max: 60, unit: 's' },
        ],
      },
      {
        id: 'interface', items: [
          { key: 'lang', type: 'select', options: ['en', 'de', 'fr', 'es'] },
          { key: 'theme', type: 'select', options: ['dark', 'light'] },
          { key: 'fontSize', type: 'number', min: 80, max: 150, step: 10, unit: '%' },
          { key: 'colorizePasswords', type: 'toggle' },
          { key: 'monospaceNotes', type: 'toggle' },
          { key: 'trayIcon', type: 'toggle' },
          { key: 'trayStyle', type: 'select', options: ['colorful', 'monoLight', 'monoDark'], dependsOn: 'trayIcon' },
          { key: 'hideToTray', type: 'toggle', dependsOn: 'trayIcon' },
        ],
      },
      {
        id: 'manage', items: [
          { key: 'export', type: 'action' },
          { key: 'import', type: 'action' },
          { key: 'reset', type: 'action' },
        ],
      },
    ],
  },
  {
    id: 'autotype', icon: 'keyboard', groups: [
      {
        id: 'autotype', items: [
          { key: 'atMatchTitle', type: 'toggle' },
          { key: 'atMatchUrl', type: 'toggle' },
          { key: 'atAlwaysAsk', type: 'toggle' },
          { key: 'atHideExpired', type: 'toggle' },
          { key: 'atRelock', type: 'toggle' },
          { key: 'atShortcut', type: 'shortcut' },
          { key: 'atRemember', type: 'number', min: 0, max: 60, unit: 's' },
          { key: 'atStartDelay', type: 'number', min: 100, max: 10000, step: 100, unit: 'ms' },
          { key: 'atCharDelay', type: 'number', min: 0, max: 1000, unit: 'ms' },
        ],
      },
    ],
  },
  {
    id: 'security', icon: 'shield_lock', groups: [
      {
        id: 'timeouts', items: [
          { key: 'clipboardClear', type: 'toggle' },
          { key: 'clipboardSeconds', type: 'number', min: 1, max: 999, unit: 's', dependsOn: 'clipboardClear' },
          { key: 'autoLock', type: 'toggle' },
          { key: 'autoLockSeconds', type: 'number', min: 10, max: 43200, unit: 's', dependsOn: 'autoLock' },
          { key: 'clearSearch', type: 'toggle' },
          { key: 'clearSearchMinutes', type: 'number', min: 1, max: 1440, unit: 'min', dependsOn: 'clearSearch' },
        ],
      },
      {
        id: 'lock', items: [
          { key: 'quickUnlock', type: 'toggle' },
          { key: 'lockOnSession', type: 'toggle' },
          { key: 'lockOnUserSwitch', type: 'toggle' },
          { key: 'lockOnMinimize', type: 'toggle' },
        ],
      },
      {
        id: 'display', items: [
          { key: 'passwordPlaceholder', type: 'toggle' },
          { key: 'hideInEdit', type: 'toggle' },
          { key: 'hidePwPreview', type: 'toggle' },
          { key: 'hideTotpPreview', type: 'toggle' },
          { key: 'hideNotesPreview', type: 'toggle' },
        ],
      },
      { id: 'privacy', items: [{ key: 'ddgFavicons', type: 'toggle' }] },
    ],
  },
  {
    id: 'browser', icon: 'travel_explore', groups: [
      {
        id: 'browserGeneral', items: [
          { key: 'browserEnabled', type: 'toggle' },
          { key: 'bChrome', type: 'toggle', dependsOn: 'browserEnabled' },
          { key: 'bFirefox', type: 'toggle', dependsOn: 'browserEnabled' },
          { key: 'bChromium', type: 'toggle', dependsOn: 'browserEnabled' },
          { key: 'bEdge', type: 'toggle', dependsOn: 'browserEnabled' },
          { key: 'bBrave', type: 'toggle', dependsOn: 'browserEnabled' },
          { key: 'bVivaldi', type: 'toggle', dependsOn: 'browserEnabled' },
          { key: 'bTor', type: 'toggle', dependsOn: 'browserEnabled' },
          { key: 'bUnlock', type: 'toggle', dependsOn: 'browserEnabled' },
          { key: 'bMatchScheme', type: 'toggle', dependsOn: 'browserEnabled' },
          { key: 'bBestMatch', type: 'toggle', dependsOn: 'browserEnabled' },
          { key: 'bAllowExpired', type: 'toggle', dependsOn: 'browserEnabled' },
          { key: 'bSearchAll', type: 'toggle', dependsOn: 'browserEnabled' },
        ],
      },
      {
        id: 'browserAdvanced', items: [
          { key: 'bNoAccessConfirm', type: 'toggle', dependsOn: 'browserEnabled' },
          { key: 'bUpdateNoConfirm', type: 'toggle', dependsOn: 'browserEnabled' },
          { key: 'bSkipBasicAuth', type: 'toggle', dependsOn: 'browserEnabled' },
          { key: 'bKph', type: 'toggle', dependsOn: 'browserEnabled' },
          { key: 'bLocalhostPasskeys', type: 'toggle', dependsOn: 'browserEnabled', planned: true },
          { key: 'bUpdateManifests', type: 'toggle', dependsOn: 'browserEnabled' },
          { key: 'bCustomProxy', type: 'toggle', dependsOn: 'browserEnabled' },
          { key: 'bProxyPath', type: 'path', dependsOn: 'bCustomProxy' },
        ],
      },
      {
        id: 'browserCustom', items: [
          { key: 'bCustomBrowser', type: 'toggle', dependsOn: 'browserEnabled', platform: 'linux-mac', planned: true },
          { key: 'bCustomType', type: 'select', options: ['firefox', 'chromium'], dependsOn: 'bCustomBrowser', platform: 'linux-mac', planned: true },
          { key: 'bCustomPath', type: 'path', dependsOn: 'bCustomBrowser', platform: 'linux-mac', planned: true },
        ],
      },
    ],
  },
  {
    id: 'ssh', icon: 'terminal', groups: [
      {
        id: 'ssh', items: [
          { key: 'sshEnabled', type: 'toggle' },
          { key: 'sshStatus', type: 'info', value: '—' },
          { key: 'sshAuthSockCurrent', type: 'info', value: '—' },
          { key: 'sshAuthSock', type: 'path', dependsOn: 'sshEnabled' },
        ],
      },
    ],
  },
  {
    // reminder for the hybrid roadmap (M6): visible but inert until server vaults exist
    id: 'servers', icon: 'cloud_sync', groups: [
      {
        id: 'serversWip', items: [
          { key: 'bwConnect', type: 'action', wip: true },
          { key: 'vwConnect', type: 'action', wip: true },
        ],
      },
    ],
  },
  {
    id: 'keeshare', icon: 'share', groups: [
      {
        id: 'ksActivation', items: [
          { key: 'ksImport', type: 'toggle' },
          { key: 'ksExport', type: 'toggle' },
        ],
      },
    ],
  },
];

const SCHEMA = new Map(SECTIONS.flatMap(s => s.groups.flatMap(g => g.items)).map(i => [i.key, i] as const));

export const clamp = (n: number, min: number, max: number) => Math.min(max, Math.max(min, Math.round(n)));

/** Merge stored/imported JSON over defaults. Unknown keys, wrong types and invalid
 *  select values are dropped; numbers are clamped to their allowed range. */
export function mergePrefs(raw: unknown): Prefs {
  const out: Record<string, unknown> = { ...DEFAULTS };
  if (!raw || typeof raw !== 'object') return out as Prefs;
  for (const [k, v] of Object.entries(raw)) {
    if (!(k in DEFAULTS) || typeof v !== typeof (DEFAULTS as Record<string, unknown>)[k]) continue;
    const s = SCHEMA.get(k as PrefKey);
    if (s?.type === 'number') out[k] = Number.isFinite(v) ? clamp(v as number, s.min, s.max) : out[k];
    else if (s?.type === 'select') { if (s.options.includes(v as string)) out[k] = v; }
    else out[k] = v;
  }
  return out as Prefs;
}
