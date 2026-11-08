// Color schemes as data: the base colors of every scheme (same values as src/index.css) for the
// preview cards, the "follow system" theme, and the user's own scheme, which is applied as inline
// --p-* variables so the same derivation as for the built-in schemes takes over.

export type Mode = 'dark' | 'light';
export type Theme = 'dark' | 'light' | 'oled';
export type ThemeSetting = Theme | 'system';
export interface Colors { bg: string; fg: string; acc: string }

export const SCHEMES: Record<string, Record<Mode, Colors>> = {
  terracotta: { dark: { bg: '#17130f', fg: '#ece0d4', acc: '#ffb68b' }, light: { bg: '#fff8f3', fg: '#221a14', acc: '#8f4c21' } },
  nord: { dark: { bg: '#2e3440', fg: '#eceff4', acc: '#88c0d0' }, light: { bg: '#eceff4', fg: '#2e3440', acc: '#5e81ac' } },
  gruvbox: { dark: { bg: '#282828', fg: '#ebdbb2', acc: '#fe8019' }, light: { bg: '#fbf1c7', fg: '#3c3836', acc: '#af3a03' } },
  solarized: { dark: { bg: '#002b36', fg: '#eee8d5', acc: '#268bd2' }, light: { bg: '#fdf6e3', fg: '#073642', acc: '#268bd2' } },
  rosepine: { dark: { bg: '#191724', fg: '#e0def4', acc: '#ebbcba' }, light: { bg: '#faf4ed', fg: '#575279', acc: '#b4637a' } },
  everforest: { dark: { bg: '#2d353b', fg: '#d3c6aa', acc: '#a7c080' }, light: { bg: '#fdf6e3', fg: '#5c6a72', acc: '#687d00' } },
  tokyonight: { dark: { bg: '#1a1b26', fg: '#c0caf5', acc: '#7aa2f7' }, light: { bg: '#e1e2e7', fg: '#343b58', acc: '#2e7de9' } },
  dracula: { dark: { bg: '#282a36', fg: '#f8f8f2', acc: '#bd93f9' }, light: { bg: '#fffbeb', fg: '#1f1f1f', acc: '#644ac9' } },
};

/** the user's own scheme, as stored in the settings */
export interface CustomColors {
  customDarkBg: string; customDarkFg: string; customDarkAcc: string;
  customLightBg: string; customLightFg: string; customLightAcc: string;
}
export const CUSTOM_DEFAULTS: CustomColors = {
  customDarkBg: '#1e1e2e', customDarkFg: '#cdd6f4', customDarkAcc: '#89b4fa',
  customLightBg: '#eff1f5', customLightFg: '#4c4f69', customLightAcc: '#1e66f5',
};
export const customOf = (p: CustomColors, mode: Mode): Colors => mode === 'dark'
  ? { bg: p.customDarkBg, fg: p.customDarkFg, acc: p.customDarkAcc }
  : { bg: p.customLightBg, fg: p.customLightFg, acc: p.customLightAcc };

export const colorsOf = (scheme: string, mode: Mode, p: CustomColors): Colors =>
  scheme === 'custom' ? customOf(p, mode) : (SCHEMES[scheme] ?? SCHEMES.terracotta)[mode];

export const isHex = (v: unknown): v is string => typeof v === 'string' && /^#[0-9a-f]{6}$/i.test(v);

/** "system" follows Windows' light/dark setting; dark then means dark or OLED (systemDark) */
export function resolveTheme(theme: ThemeSetting, systemDark: Theme, prefersDark: boolean): Theme {
  if (theme !== 'system') return theme;
  return prefersDark ? (systemDark === 'oled' ? 'oled' : 'dark') : 'light';
}

export const prefersDark = () => typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: dark)').matches;

/** WCAG contrast ratio of two #rrggbb colors (1 … 21) */
export function contrast(a: string, b: string): number {
  const lum = (hex: string) => {
    const c = [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16) / 255)
      .map(v => v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4);
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
  };
  const [x, y] = [lum(a), lum(b)].sort((m, n) => n - m);
  return (x + 0.05) / (y + 0.05);
}

/** Theme, scheme and own colors on <html>, from (possibly partial) stored settings. Returns the
 *  theme in effect. Main window and quick access window share it. */
export function applyLook(s: Partial<CustomColors> & { theme?: string; systemDark?: string; accent?: string }): Theme {
  const el = document.documentElement;
  const theme = resolveTheme((s.theme ?? 'dark') as ThemeSetting, (s.systemDark ?? 'dark') as Theme, prefersDark());
  const accent = s.accent ?? 'terracotta';
  el.dataset.theme = theme;
  el.dataset.accent = accent;
  const own = Object.fromEntries(Object.entries(CUSTOM_DEFAULTS).map(([k, v]) => {
    const x = (s as Record<string, unknown>)[k];
    return [k, isHex(x) ? x : v];
  })) as unknown as CustomColors;
  applyScheme(el, accent, theme, own);
  return theme;
}

const CUSTOM_VARS =['--p-bg', '--p-fg', '--p-acc', '--p-on-acc', '--p-sec', '--p-ter', '--p-err', '--p-x1', '--p-x2'];

/** Put the user's own scheme on <html> (or take it off again for a built-in scheme). The other
 *  base colors are mixed from the three chosen ones, like the built-in schemes' derivation. */
export function applyScheme(el: HTMLElement, scheme: string, theme: Theme, p: CustomColors) {
  if (scheme !== 'custom') { CUSTOM_VARS.forEach(v => el.style.removeProperty(v)); return; }
  const mode: Mode = theme === 'light' ? 'light' : 'dark';
  const c = customOf(p, mode);
  const onAcc = contrast(c.acc, '#000000') > contrast(c.acc, '#ffffff') ? '#000000' : '#ffffff';
  const mix = (other: string, pct: number) => `color-mix(in oklab, ${c.acc} ${pct}%, ${other})`;
  const vars: Record<string, string> = {
    '--p-bg': c.bg, '--p-fg': c.fg, '--p-acc': c.acc, '--p-on-acc': onAcc,
    '--p-sec': mix(c.fg, 55), '--p-ter': mix('#d9a400', 35), '--p-err': mode === 'light' ? '#ba1a1a' : '#ffb4ab',
    '--p-x1': mix('#c062b0', 35), '--p-x2': mix('#2fa3ae', 35),
  };
  for (const [k, v] of Object.entries(vars)) el.style.setProperty(k, v);
}
