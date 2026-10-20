// Application settings: one schema drives defaults, the settings page and import validation.
// Defaults follow KeePassXC. `desktop: true` = stored now, takes effect once the Tauri backend exists.
import type { Lang } from './i18n';

export const DEFAULTS = {
  lang: 'en' as Lang,
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
  autosaveChange: true,
  autosaveLock: true,
  saveNonData: false,
  autoReload: true,
  backupBeforeSave: false,
  backupPath: '{DB_FILENAME}.old.kdbx',
  altSave: false,
  altSaveMode: 'temp',
  // General · entries
  confirmTrash: true,
  generateForNew: true,
  copyOnDoubleClick: false,
  urlDoubleClick: 'open',
  useGroupIcon: true,
  minimizeOnUrl: false,
  onCopy: 'none',
  faviconTimeout: 10,
  // General · interface
  fontSize: 100,
  toolbarStyle: 'follow',
  toolbarMovable: false,
  showToolbar: true,
  showMenubar: true,
  colorizePasswords: true,
  monospaceNotes: false,
  minimizeOnClose: false,
  trayIcon: true,
  trayStyle: 'colorful',
  hideToTray: false,

  // Auto-Type
  atMatchTitle: true,
  atMatchUrl: true,
  atAlwaysAsk: true,
  atSkipConfirmMain: false,
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
  bNoMigration: false,
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
  | { key: PrefKey; type: 'toggle' | 'text' | 'path' | 'shortcut'; desktop?: boolean; dependsOn?: PrefKey; platform?: Platform }
  | { key: PrefKey; type: 'number'; min: number; max: number; unit: 's' | 'ms' | 'min' | 'd' | '%' | ''; step?: number; desktop?: boolean; dependsOn?: PrefKey; platform?: Platform }
  | { key: PrefKey; type: 'select'; options: string[]; desktop?: boolean; dependsOn?: PrefKey; platform?: Platform }
  | { key: 'sshStatus' | 'sshAuthSockCurrent' | 'skProviderCurrent' | 'ksFingerprint'; type: 'info'; value: string; platform?: Platform }
  | { key: 'reset' | 'import' | 'export' | 'ksGenerate' | 'bwConnect' | 'vwConnect'; type: 'action'; desktop?: boolean; wip?: boolean };

export type Platform = 'windows' | 'linux-mac';
export interface Group { id: string; items: Setting[] }
export interface Section { id: string; icon: string; groups: Group[] }

const d = true; // marker: needs desktop backend

export const SECTIONS: Section[] = [
  {
    id: 'general', icon: 'tune', groups: [
      {
        id: 'startup', items: [
          { key: 'singleInstance', type: 'toggle', desktop: d },
          { key: 'autostart', type: 'toggle', desktop: d },
          { key: 'startMinimized', type: 'toggle', desktop: d },
          { key: 'minimizeAfterUnlock', type: 'toggle', desktop: d },
          { key: 'rememberRecent', type: 'toggle', desktop: d },
          { key: 'recentCount', type: 'number', min: 1, max: 25, unit: '', dependsOn: 'rememberRecent', desktop: d },
          { key: 'reopenLast', type: 'toggle', dependsOn: 'rememberRecent', desktop: d },
          { key: 'rememberKeyfiles', type: 'toggle', dependsOn: 'rememberRecent', desktop: d },
          { key: 'updateCheck', type: 'toggle', desktop: d },
          { key: 'updateBeta', type: 'toggle', dependsOn: 'updateCheck', desktop: d },
          { key: 'showExpiring', type: 'toggle', desktop: d },
          { key: 'expiryDays', type: 'number', min: 0, max: 90, unit: 'd', dependsOn: 'showExpiring', desktop: d },
        ],
      },
      {
        id: 'files', items: [
          { key: 'autosaveChange', type: 'toggle', desktop: d },
          { key: 'autosaveLock', type: 'toggle', desktop: d },
          { key: 'saveNonData', type: 'toggle', dependsOn: 'autosaveLock', desktop: d },
          { key: 'autoReload', type: 'toggle', desktop: d },
          { key: 'backupBeforeSave', type: 'toggle', desktop: d },
          { key: 'backupPath', type: 'path', dependsOn: 'backupBeforeSave', desktop: d },
          { key: 'altSave', type: 'toggle', desktop: d },
          { key: 'altSaveMode', type: 'select', options: ['temp', 'direct'], dependsOn: 'altSave', desktop: d },
        ],
      },
      {
        id: 'entries', items: [
          { key: 'confirmTrash', type: 'toggle' },
          { key: 'generateForNew', type: 'toggle' },
          { key: 'copyOnDoubleClick', type: 'toggle' },
          { key: 'urlDoubleClick', type: 'select', options: ['open', 'copy', 'edit'] },
          { key: 'useGroupIcon', type: 'toggle', desktop: d },
          { key: 'minimizeOnUrl', type: 'toggle', desktop: d },
          { key: 'onCopy', type: 'select', options: ['none', 'minimize', 'background'], desktop: d },
          { key: 'faviconTimeout', type: 'number', min: 1, max: 60, unit: 's', desktop: d },
        ],
      },
      {
        id: 'interface', items: [
          { key: 'lang', type: 'select', options: ['en', 'de', 'fr', 'es'] },
          { key: 'theme', type: 'select', options: ['dark', 'light'] },
          { key: 'fontSize', type: 'number', min: 80, max: 150, step: 10, unit: '%' },
          { key: 'colorizePasswords', type: 'toggle' },
          { key: 'monospaceNotes', type: 'toggle' },
          { key: 'toolbarStyle', type: 'select', options: ['follow', 'icons', 'text', 'both'], desktop: d },
          { key: 'toolbarMovable', type: 'toggle', desktop: d },
          { key: 'showToolbar', type: 'toggle', desktop: d },
          { key: 'showMenubar', type: 'toggle', desktop: d },
          { key: 'minimizeOnClose', type: 'toggle', desktop: d },
          { key: 'trayIcon', type: 'toggle', desktop: d },
          { key: 'trayStyle', type: 'select', options: ['colorful', 'monoLight', 'monoDark'], dependsOn: 'trayIcon', desktop: d },
          { key: 'hideToTray', type: 'toggle', dependsOn: 'trayIcon', desktop: d },
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
          { key: 'atMatchTitle', type: 'toggle', desktop: d },
          { key: 'atMatchUrl', type: 'toggle', desktop: d },
          { key: 'atAlwaysAsk', type: 'toggle', desktop: d },
          { key: 'atSkipConfirmMain', type: 'toggle', desktop: d },
          { key: 'atHideExpired', type: 'toggle', desktop: d },
          { key: 'atRelock', type: 'toggle', desktop: d },
          { key: 'atShortcut', type: 'shortcut', desktop: d },
          { key: 'atRemember', type: 'number', min: 0, max: 60, unit: 's', desktop: d },
          { key: 'atStartDelay', type: 'number', min: 100, max: 10000, step: 100, unit: 'ms', desktop: d },
          { key: 'atCharDelay', type: 'number', min: 0, max: 1000, unit: 'ms', desktop: d },
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
          { key: 'quickUnlock', type: 'toggle', desktop: d },
          { key: 'lockOnSession', type: 'toggle', desktop: d },
          { key: 'lockOnUserSwitch', type: 'toggle', desktop: d },
          { key: 'lockOnMinimize', type: 'toggle', desktop: d },
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
      { id: 'privacy', items: [{ key: 'ddgFavicons', type: 'toggle', desktop: d }] },
    ],
  },
  {
    id: 'browser', icon: 'travel_explore', groups: [
      {
        id: 'browserGeneral', items: [
          { key: 'browserEnabled', type: 'toggle', desktop: d },
          { key: 'bChrome', type: 'toggle', dependsOn: 'browserEnabled', desktop: d },
          { key: 'bFirefox', type: 'toggle', dependsOn: 'browserEnabled', desktop: d },
          { key: 'bChromium', type: 'toggle', dependsOn: 'browserEnabled', desktop: d },
          { key: 'bEdge', type: 'toggle', dependsOn: 'browserEnabled', desktop: d },
          { key: 'bBrave', type: 'toggle', dependsOn: 'browserEnabled', desktop: d },
          { key: 'bVivaldi', type: 'toggle', dependsOn: 'browserEnabled', desktop: d },
          { key: 'bTor', type: 'toggle', dependsOn: 'browserEnabled', desktop: d },
          { key: 'bUnlock', type: 'toggle', dependsOn: 'browserEnabled', desktop: d },
          { key: 'bMatchScheme', type: 'toggle', dependsOn: 'browserEnabled', desktop: d },
          { key: 'bBestMatch', type: 'toggle', dependsOn: 'browserEnabled', desktop: d },
          { key: 'bAllowExpired', type: 'toggle', dependsOn: 'browserEnabled', desktop: d },
          { key: 'bSearchAll', type: 'toggle', dependsOn: 'browserEnabled', desktop: d },
        ],
      },
      {
        id: 'browserAdvanced', items: [
          { key: 'bNoAccessConfirm', type: 'toggle', dependsOn: 'browserEnabled', desktop: d },
          { key: 'bUpdateNoConfirm', type: 'toggle', dependsOn: 'browserEnabled', desktop: d },
          { key: 'bSkipBasicAuth', type: 'toggle', dependsOn: 'browserEnabled', desktop: d },
          { key: 'bKph', type: 'toggle', dependsOn: 'browserEnabled', desktop: d },
          { key: 'bLocalhostPasskeys', type: 'toggle', dependsOn: 'browserEnabled', desktop: d },
          { key: 'bNoMigration', type: 'toggle', dependsOn: 'browserEnabled', desktop: d },
          { key: 'bUpdateManifests', type: 'toggle', dependsOn: 'browserEnabled', desktop: d },
          { key: 'bCustomProxy', type: 'toggle', dependsOn: 'browserEnabled', desktop: d },
          { key: 'bProxyPath', type: 'path', dependsOn: 'bCustomProxy', desktop: d },
        ],
      },
      {
        id: 'browserCustom', items: [
          { key: 'bCustomBrowser', type: 'toggle', dependsOn: 'browserEnabled', platform: 'linux-mac', desktop: d },
          { key: 'bCustomType', type: 'select', options: ['firefox', 'chromium'], dependsOn: 'bCustomBrowser', platform: 'linux-mac', desktop: d },
          { key: 'bCustomPath', type: 'path', dependsOn: 'bCustomBrowser', platform: 'linux-mac', desktop: d },
        ],
      },
    ],
  },
  {
    id: 'ssh', icon: 'terminal', groups: [
      {
        id: 'ssh', items: [
          { key: 'sshEnabled', type: 'toggle', desktop: d },
          { key: 'sshStatus', type: 'info', value: '—' },
          { key: 'sshAgent', type: 'select', options: ['pageant', 'openssh', 'bothAgents'], dependsOn: 'sshEnabled', platform: 'windows', desktop: d },
          { key: 'sshAuthSockCurrent', type: 'info', value: '—' },
          { key: 'sshAuthSock', type: 'path', dependsOn: 'sshEnabled', desktop: d },
          { key: 'skProviderCurrent', type: 'info', value: '—' },
          { key: 'skProvider', type: 'path', dependsOn: 'sshEnabled', desktop: d },
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
          { key: 'ksImport', type: 'toggle', desktop: d },
          { key: 'ksExport', type: 'toggle', desktop: d },
          { key: 'ksQuiet', type: 'toggle', desktop: d },
        ],
      },
      {
        id: 'ksCert', items: [
          { key: 'ksSigner', type: 'text', desktop: d },
          { key: 'ksFingerprint', type: 'info', value: '—' },
          { key: 'ksGenerate', type: 'action', desktop: d },
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
