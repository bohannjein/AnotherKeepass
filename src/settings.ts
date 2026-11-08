// Application settings: one schema drives defaults, the settings page and import validation.
// Defaults follow KeePassXC. `planned: true` = stored, but the feature is not built yet (hidden unless "show planned").
import { CUSTOM_DEFAULTS, isHex } from './schemes.ts';
import type { Lang } from './i18n';

export const DEFAULTS = {
  lang: 'en' as Lang,
  theme: 'dark' as 'system' | 'dark' | 'light' | 'oled',
  /** what "dark" means while following the system */
  systemDark: 'dark' as 'dark' | 'oled',

  // General · startup
  singleInstance: true,
  autostart: false,
  startMinimized: false,
  minimizeAfterUnlock: false,
  rememberRecent: true,
  recentCount: 5,
  reopenLast: true,
  rememberKeyfiles: true,
  updateAuto: true,
  updateNotify: true,
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
  drawerWidth: 272,
  listWidth: 360,
  accent: 'terracotta',
  // own color scheme (accent: 'custom')
  ...CUSTOM_DEFAULTS,
  listDensity: 'comfortable',
  letterAvatars: true,
  colorizePasswords: true,
  monospaceNotes: false,
  trayIcon: true,
  trayStyle: 'monoLight',
  hideToTray: false,

  // Auto-Type
  atMatchTitle: true,
  atMatchUrl: true,
  atAlwaysAsk: true,
  atHideExpired: false,
  atRelock: false,
  atShortcut: '',
  quickShortcut: 'Ctrl+Alt+K',
  atRemember: 10,
  atStartDelay: 500,
  atCharDelay: 25,

  // Security
  clipboardClear: true,
  clipboardSeconds: 10,
  autoLock: false,
  autoLockSeconds: 300,
  clearSearch: true,
  clearSearchMinutes: 5,
  helloUnlock: false,
  helloRequirePassword: false,
  lockOnSession: true,
  lockOnUserSwitch: true,
  screenProtect: true,
  lockOnMinimize: false,
  passwordPlaceholder: false,
  hideInEdit: true,
  hidePwPreview: true,
  revealSeconds: 20,
  entrySort: 'used', // was listSort ('title'); the new name gives everyone the new default once
  listGroup: 'none',
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

/** `advanced`: behind "Advanced" at the end of its section (search still finds it).
 *  `presets` (numbers): one-tap choices instead of typing; `never` is the switch that "Never"
 *  turns off (or, as a number, the value that means never), so switch and time are one row. */
type Common = { planned?: boolean; dependsOn?: PrefKey; platform?: Platform; advanced?: boolean };
export type Setting =
  | ({ key: PrefKey; type: 'toggle' | 'text' | 'path' | 'shortcut' } & Common)
  | ({ key: PrefKey; type: 'number'; min: number; max: number; unit: 's' | 'ms' | 'min' | 'd' | '%' | ''; step?: number; presets?: number[]; never?: PrefKey | number } & Common)
  | ({ key: PrefKey; type: 'select'; options: string[] } & Common)
  | { key: 'sshStatus' | 'sshAuthSockCurrent' | 'skProviderCurrent' | 'ksFingerprint'; type: 'info'; value: string; platform?: Platform; advanced?: boolean }
  | { key: 'reset' | 'import' | 'export' | 'updateNow' | 'layoutReset' | 'ksGenerate' | 'bwConnect' | 'vwConnect'; type: 'action'; planned?: boolean; wip?: boolean; advanced?: boolean };

export type Platform = 'windows' | 'linux-mac';
export interface Group { id: string; items: Setting[] }
/** `tint`: color of the icon tile in the sidebar; `block`: starts a new block of the sidebar */
export interface Section { id: string; icon: string; tint: string; block?: boolean; groups: Group[] }


/** Options marked with a platform only show up there (Windows Hello, Windows session events, …). */
export const IS_WINDOWS = typeof navigator !== 'undefined' && /Windows/.test(navigator.userAgent);
export const onThisPlatform = (s: Setting) => !('platform' in s && s.platform) || (s.platform === 'windows') === IS_WINDOWS;

export const SECTIONS: Section[] = [
  {
    id: 'general', icon: 'tune', tint: '--v-sand', groups: [
      {
        id: 'startup', items: [
          { key: 'autostart', type: 'toggle' },
          { key: 'startMinimized', type: 'toggle' },
          { key: 'singleInstance', type: 'toggle', advanced: true },
          { key: 'minimizeAfterUnlock', type: 'toggle', advanced: true },
        ],
      },
      {
        id: 'recent', items: [
          { key: 'rememberRecent', type: 'toggle' },
          { key: 'reopenLast', type: 'toggle', dependsOn: 'rememberRecent' },
          { key: 'recentCount', type: 'number', min: 1, max: 25, unit: '', dependsOn: 'rememberRecent', advanced: true },
          { key: 'rememberKeyfiles', type: 'toggle', dependsOn: 'rememberRecent', advanced: true },
        ],
      },
      {
        id: 'updates', items: [
          { key: 'updateAuto', type: 'toggle' },
          { key: 'updateNotify', type: 'toggle' },
          { key: 'updateNow', type: 'action' },
          { key: 'updateBeta', type: 'toggle', advanced: true },
        ],
      },
      {
        id: 'ssh', items: [
          { key: 'sshEnabled', type: 'toggle', advanced: true },
          { key: 'sshStatus', type: 'info', value: '—', advanced: true },
          { key: 'sshAuthSockCurrent', type: 'info', value: '—', advanced: true },
          { key: 'sshAuthSock', type: 'path', dependsOn: 'sshEnabled', advanced: true },
        ],
      },
      {
        id: 'ksActivation', items: [
          { key: 'ksImport', type: 'toggle', advanced: true },
          { key: 'ksExport', type: 'toggle', advanced: true },
        ],
      },
    ],
  },
  {
    id: 'security', icon: 'shield_lock', tint: '--v-clay', groups: [
      {
        id: 'lock', items: [
          { key: 'autoLockSeconds', type: 'number', min: 10, max: 43200, unit: 's', presets: [60, 300, 900, 3600], never: 'autoLock' },
          { key: 'lockOnSession', type: 'toggle' },
          { key: 'lockOnUserSwitch', type: 'toggle', platform: 'windows', advanced: true },
          { key: 'lockOnMinimize', type: 'toggle', advanced: true },
        ],
      },
      {
        id: 'unlock', items: [
          { key: 'helloUnlock', type: 'toggle', platform: 'windows' },
          { key: 'helloRequirePassword', type: 'toggle', dependsOn: 'helloUnlock', platform: 'windows', advanced: true },
        ],
      },
      {
        id: 'timeouts', items: [
          { key: 'clipboardSeconds', type: 'number', min: 1, max: 999, unit: 's', presets: [10, 30, 60], never: 'clipboardClear' },
          { key: 'clearSearchMinutes', type: 'number', min: 1, max: 1440, unit: 'min', presets: [1, 5, 15], never: 'clearSearch', advanced: true },
        ],
      },
      {
        id: 'screen', items: [
          { key: 'screenProtect', type: 'toggle', platform: 'windows' },
        ],
      },
    ],
  },
  {
    id: 'appearance', icon: 'palette', tint: '--v-plum', groups: [
      {
        id: 'look', items: [
          { key: 'theme', type: 'select', options: ['system', 'dark', 'light', 'oled'] },
          { key: 'systemDark', type: 'select', options: ['dark', 'oled'] },
          { key: 'accent', type: 'select', options: ['terracotta', 'nord', 'gruvbox', 'solarized', 'rosepine', 'everforest', 'tokyonight', 'dracula', 'custom'] },
          { key: 'lang', type: 'select', options: ['en', 'de', 'fr', 'es'] },
          { key: 'fontSize', type: 'number', min: 80, max: 150, step: 10, unit: '%', presets: [90, 100, 115, 130] },
          { key: 'layoutReset', type: 'action', advanced: true },
        ],
      },
      {
        id: 'tray', items: [
          { key: 'trayIcon', type: 'toggle' },
          { key: 'hideToTray', type: 'toggle', dependsOn: 'trayIcon' },
          { key: 'trayStyle', type: 'select', options: ['colorful', 'monoLight', 'monoDark'], dependsOn: 'trayIcon', advanced: true },
        ],
      },
      {
        id: 'list', items: [
          { key: 'listDensity', type: 'select', options: ['comfortable', 'compact'], advanced: true },
          { key: 'letterAvatars', type: 'toggle', advanced: true },
          { key: 'colorizePasswords', type: 'toggle', advanced: true },
          { key: 'monospaceNotes', type: 'toggle', advanced: true },
        ],
      },
    ],
  },
  {
    id: 'browser', icon: 'travel_explore', tint: '--v-sea', groups: [
      {
        id: 'browserGeneral', items: [
          { key: 'browserEnabled', type: 'toggle' },
          { key: 'bUnlock', type: 'toggle', dependsOn: 'browserEnabled' },
        ],
      },
      {
        id: 'shortcuts', items: [
          { key: 'quickShortcut', type: 'shortcut' },
          { key: 'atShortcut', type: 'shortcut' },
        ],
      },
      {
        id: 'browsers', items: [
          { key: 'bChrome', type: 'toggle', dependsOn: 'browserEnabled', advanced: true },
          { key: 'bFirefox', type: 'toggle', dependsOn: 'browserEnabled', advanced: true },
          { key: 'bChromium', type: 'toggle', dependsOn: 'browserEnabled', advanced: true },
          { key: 'bEdge', type: 'toggle', dependsOn: 'browserEnabled', advanced: true },
          { key: 'bBrave', type: 'toggle', dependsOn: 'browserEnabled', advanced: true },
          { key: 'bVivaldi', type: 'toggle', dependsOn: 'browserEnabled', advanced: true },
          { key: 'bTor', type: 'toggle', dependsOn: 'browserEnabled', advanced: true },
        ],
      },
      {
        id: 'matching', items: [
          { key: 'bMatchScheme', type: 'toggle', dependsOn: 'browserEnabled', advanced: true },
          { key: 'bBestMatch', type: 'toggle', dependsOn: 'browserEnabled', advanced: true },
          { key: 'bAllowExpired', type: 'toggle', dependsOn: 'browserEnabled', advanced: true },
          { key: 'bSearchAll', type: 'toggle', dependsOn: 'browserEnabled', advanced: true },
        ],
      },
      {
        id: 'browserAdvanced', items: [
          { key: 'bNoAccessConfirm', type: 'toggle', dependsOn: 'browserEnabled', advanced: true },
          { key: 'bUpdateNoConfirm', type: 'toggle', dependsOn: 'browserEnabled', advanced: true },
          { key: 'bSkipBasicAuth', type: 'toggle', dependsOn: 'browserEnabled', advanced: true },
          { key: 'bKph', type: 'toggle', dependsOn: 'browserEnabled', advanced: true },
          { key: 'bLocalhostPasskeys', type: 'toggle', dependsOn: 'browserEnabled', advanced: true },
          { key: 'bUpdateManifests', type: 'toggle', dependsOn: 'browserEnabled', advanced: true },
          { key: 'bCustomProxy', type: 'toggle', dependsOn: 'browserEnabled', advanced: true },
          { key: 'bProxyPath', type: 'path', dependsOn: 'bCustomProxy', advanced: true },
        ],
      },
      {
        id: 'autotype', items: [
          { key: 'atMatchTitle', type: 'toggle', advanced: true },
          { key: 'atMatchUrl', type: 'toggle', advanced: true },
          { key: 'atAlwaysAsk', type: 'toggle', advanced: true },
          { key: 'atHideExpired', type: 'toggle', advanced: true },
          { key: 'atRelock', type: 'toggle', advanced: true },
          { key: 'atRemember', type: 'number', min: 0, max: 60, unit: 's', advanced: true },
          { key: 'atStartDelay', type: 'number', min: 100, max: 10000, step: 100, unit: 'ms', advanced: true },
          { key: 'atCharDelay', type: 'number', min: 0, max: 1000, unit: 'ms', advanced: true },
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
    id: 'entries', icon: 'folder_open', tint: '--v-ochre', groups: [
      {
        id: 'entries', items: [
          { key: 'confirmTrash', type: 'toggle' },
          { key: 'generateForNew', type: 'toggle' },
          { key: 'expiryDays', type: 'number', min: 0, max: 90, unit: 'd', presets: [3, 7, 14, 30], never: 'showExpiring' },
          { key: 'revealSeconds', type: 'number', min: 0, max: 600, unit: 's', presets: [10, 30, 60], never: 0 },
          { key: 'copyOnDoubleClick', type: 'toggle', advanced: true },
          { key: 'urlDoubleClick', type: 'select', options: ['open', 'copy', 'edit'], advanced: true },
          { key: 'minimizeOnUrl', type: 'toggle', advanced: true },
          { key: 'onCopy', type: 'select', options: ['none', 'minimize', 'background'], advanced: true },
          { key: 'faviconTimeout', type: 'number', min: 1, max: 60, unit: 's', advanced: true },
        ],
      },
      {
        id: 'files', items: [
          { key: 'autoReload', type: 'toggle' },
          { key: 'backupBeforeSave', type: 'toggle', advanced: true },
          { key: 'backupPath', type: 'path', dependsOn: 'backupBeforeSave', advanced: true },
        ],
      },
      {
        id: 'display', items: [
          { key: 'passwordPlaceholder', type: 'toggle', advanced: true },
          { key: 'hideInEdit', type: 'toggle', advanced: true },
          { key: 'hidePwPreview', type: 'toggle', advanced: true },
          { key: 'hideTotpPreview', type: 'toggle', advanced: true },
          { key: 'hideNotesPreview', type: 'toggle', advanced: true },
          { key: 'ddgFavicons', type: 'toggle', advanced: true },
        ],
      },
    ],
  },
  {
    id: 'data', icon: 'database', tint: '--v-sand', groups: [
      {
        id: 'manage', items: [
          { key: 'export', type: 'action' },
          { key: 'import', type: 'action' },
          { key: 'reset', type: 'action' },
        ],
      },
    ],
  },
];

const SCHEMA = new Map(SECTIONS.flatMap(s => s.groups.flatMap(g => g.items)).map(i => [i.key, i] as const));

/** column widths: not on the settings page, but range-checked like its numbers */
const LAYOUT: Record<string, [number, number]> = { drawerWidth: [200, 420], listWidth: [240, 720] };

export const clamp = (n: number, min: number, max: number) => Math.min(max, Math.max(min, Math.round(n)));

/** Merge stored/imported JSON over defaults. Unknown keys, wrong types and invalid
 *  select values are dropped; numbers are clamped to their allowed range. */
export function mergePrefs(raw: unknown): Prefs {
  const out: Record<string, unknown> = { ...DEFAULTS };
  if (!raw || typeof raw !== 'object') return out as Prefs;
  for (const [k, v] of Object.entries(raw)) {
    if (!(k in DEFAULTS) || typeof v !== typeof (DEFAULTS as Record<string, unknown>)[k]) continue;
    const s = SCHEMA.get(k as PrefKey);
    const layout = LAYOUT[k];
    if (layout) out[k] = Number.isFinite(v) ? clamp(v as number, layout[0], layout[1]) : out[k];
    else if (k in CUSTOM_DEFAULTS) { if (isHex(v)) out[k] = v; }
    else if (s?.type === 'number') out[k] = Number.isFinite(v) ? clamp(v as number, s.min, s.max) : out[k];
    else if (s?.type === 'select') { if (s.options.includes(v as string)) out[k] = v; }
    else out[k] = v;
  }
  return out as Prefs;
}
