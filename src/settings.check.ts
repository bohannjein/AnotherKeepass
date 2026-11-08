// node src/settings.check.ts
import { DEFAULTS, SECTIONS, mergePrefs } from './settings.ts';

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

// updates: on by default, also for settings saved before 0.2.3 (old "updateCheck: false")
const upd = mergePrefs({ updateCheck: false, updateBeta: true }) as Record<string, unknown>;
eq(upd.updateAuto, true, 'auto update default');
eq(upd.updateNotify, true, 'update notice default');
eq(upd.updateBeta, true, 'beta kept');
eq('updateCheck' in upd, false, 'old key dropped');
eq(mergePrefs({ updateAuto: false }).updateAuto, false, 'auto update off kept');

// follow the system, own colors
eq(mergePrefs({ theme: 'system', systemDark: 'oled' }).theme, 'system', 'system theme kept');
eq(mergePrefs({ systemDark: 'pink' }).systemDark, 'dark', 'unknown system dark');
eq(mergePrefs({ accent: 'custom' }).accent, 'custom', 'own scheme kept');
eq(mergePrefs({ customDarkBg: '#123456' }).customDarkBg, '#123456', 'hex color kept');
eq(mergePrefs({ customDarkBg: 'red; x: url(evil)' }).customDarkBg, DEFAULTS.customDarkBg, 'no CSS injection');

// phone-style page: old stored values stay, presets don't overwrite them
const old = mergePrefs({ autoLock: true, autoLockSeconds: 240, clipboardClear: false, clipboardSeconds: 45 });
eq([old.autoLock, old.autoLockSeconds, old.clipboardClear, old.clipboardSeconds], [true, 240, false, 45], 'old timing values kept');
const shown = SECTIONS.flatMap(s => s.groups.flatMap(g => g.items)).filter(i => !i.advanced && !('planned' in i && i.planned));
eq(shown.length <= 32, true, `at most ~30 options without Advanced (${shown.length})`);
eq(SECTIONS.length, 6, 'six sections');

console.log('settings ok');
