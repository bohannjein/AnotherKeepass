// node src/settings.check.ts
import { DEFAULTS, mergePrefs } from './settings.ts';

const eq = (a: unknown, b: unknown, msg: string) => {
  if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${msg}: ${JSON.stringify(a)} !== ${JSON.stringify(b)}`);
};

// accent colors from before 0.2.3 fall back to the default scheme
for (const old of ['sage', 'ochre', 'plum', 'sea']) eq(mergePrefs({ accent: old }).accent, 'terracotta', 'old accent ' + old);
eq(mergePrefs({ accent: 'nord' }).accent, 'nord', 'scheme kept');
eq(mergePrefs({ accent: 'catppuccin' }).accent, 'terracotta', 'unknown scheme');

eq(mergePrefs({ theme: 'oled' }).theme, 'oled', 'oled kept');
eq(mergePrefs({ theme: 'sepia' }).theme, DEFAULTS.theme, 'unknown theme');

// column widths from an import are range-checked
eq(mergePrefs({ drawerWidth: 9999, listWidth: 10 }).drawerWidth, 420, 'drawer max');
eq(mergePrefs({ drawerWidth: 9999, listWidth: 10 }).listWidth, 240, 'list min');
eq(mergePrefs({ listWidth: 'wide' }).listWidth, DEFAULTS.listWidth, 'wrong type');
eq(mergePrefs({ drawerWidth: Number.NaN }).drawerWidth, DEFAULTS.drawerWidth, 'NaN');

console.log('settings ok');
