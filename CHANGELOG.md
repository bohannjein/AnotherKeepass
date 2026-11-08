# Changelog

## Unreleased

- **Settings, look:** theme and color scheme are picked from preview cards (a small app window
  in each scheme) instead of drop-down lists.
- **Follow the system:** new theme option that switches between light and dark with Windows,
  live. A sub-option decides whether dark means the normal dark theme or OLED black.
- **Own colors:** a ninth scheme with your own background, text and accent color for dark and
  light; the app warns when the contrast is too low.
- **Search operators** like KeePassXC: `user:`, `url:`, `notes:`, `tag:`, `title:`, `is:weak`,
  `is:reused`, `is:old`, `is:breached`, `is:expired`, `is:pinned`, `is:totp`, phrases in quotes and
  `-` to exclude. Listed in the shortcuts overview (F1) and the search field's tooltip.
- **YubiKey:** vaults protected with a YubiKey in KeePassXC (HMAC-SHA1 challenge-response, slot 1
  or 2) open and save. Pick the slot next to the key file when unlocking; it is remembered per
  vault. Not tested with real hardware yet.
- **Linux (untested):** Auto-Type reads and focuses the active window on X11 through `xdotool`;
  the browser manifests for Chrome, Chromium, Brave, Vivaldi, Edge and Firefox are written (an
  existing KeePassXC one is kept and restored); vaults lock when the screen locks (D-Bus screen
  saver signal). CI now also builds on Linux.
- **Reset column widths:** button in the settings (double-clicking a column border still works).
- **Tray icon:** a thin shield outline with a keyhole and some space around it, drawn at the
  exact tray size, so it matches the other Windows tray icons.
- **Large vaults:** the entry list only draws the rows in view once it is long (over 300 rows).
  With 5000 entries: list after unlock in 0.1 s instead of 3 s, smooth scrolling, search without
  lag. The arrow keys now scroll the list along with the selection.

## 0.2.3

- **Autostart:** with "start minimized" and the tray icon, the window could open white and
  unresponsive after logging in to Windows. The first time it is shown, it is now built fresh.
- **White window after a crash:** if WebView2 crashes (graphics driver, standby), the page
  reloads or the window is rebuilt instead of staying white. Open vaults are locked first.
- **Updates:** on by default and checked at start and once a day (was weekly and off). The
  update downloads in the background; one click installs it, and with "install automatically"
  it installs on its own while the app sits unused in the tray, then goes back there.
  "Check now" in the settings turns into "Install and restart". New switch for the notice.
- **Columns:** drag the borders between menu, list and entry to resize them (arrow keys work
  too, a double-click restores the default). Dragging the menu narrow folds it into the icon
  rail. The widths are saved.
- **Color schemes:** the accent colors are replaced by eight full color schemes, each with a
  light and a dark variant: Terracotta (default), Nord, Gruvbox, Solarized, Rosé Pine,
  Everforest, Tokyo Night and Dracula.
- **OLED black:** a new theme with pure black surfaces; it works with every color scheme.
- **Search:** also finds user names, websites, notes and custom fields (not passwords).
- **Menu footer:** settings on the left, lock on the right. The light/dark button is gone;
  the theme is in the settings and the command palette.
- **Menu header:** shows the app version and the number of entries, or a waiting update,
  instead of the "KeePass compatible" tagline.

## 0.2.2

- **Tray icon:** white shield by default, to match the Windows taskbar. It fades while every
  vault is locked, and the tooltip says "Locked".
- **Browser:** entries filled in by the browser extension count as used and show up under
  "last used" in the desktop app.
- **Unlock:** a wrong master password marks the field red, shakes it and selects the text, so
  retyping replaces it.
- **Dropdowns:** lists open in the app's colours instead of the grey Windows list.

## 0.2.1

- **Entry list and quick access:** sorted by last use by default (KeePass "last access", set
  when copying or typing). The times are saved on lock, close and quit, not on every copy, and
  never over a file that changed on disk in the meantime.
- **Quick access:** opens on the screen with the mouse, takes the keyboard focus and closes with
  Esc or a click outside it.
- **Auto-Type:** the global shortcut now picks the entry in the quick access window, with the
  matching entries on top. Enter types, Shift+Enter copies the user name, Ctrl+Enter the password.

## 0.2.0

First release with automatic updates.

- **Updates:** install from inside the app. Every update is checked against the project's
  signature before it is installed.
- **Vaultwarden organizations:** items can be edited. Collections appear as folders, new items
  go into their collection. Read-only items are refused with a clear message.
- **Password strength:** now uses zxcvbn. Words, dates, keyboard patterns and the entry's own
  data (title, user name, website) count as weak.
- **Passkeys:** a public suffix (`co.uk`, `github.io`, …) is refused as the site of a passkey.
- **Import:** damaged export files no longer break the import (found by fuzzing).
- **Quick access:** the window only exists while it is open. This fixes the empty white box
  that screen tools like TeamViewer could show.
- **Defender:** autostart and browser registration are written only when they change.
- **Hardening:**
  - Other programs can't read the app's memory.
  - The browser and SSH pipes are protected.
  - The browser protocol is stricter.
  - Account data is protected with DPAPI.
  - Vaultwarden needs https.
- **Code:**
  - GPL-3.0 license.
  - Architecture and contribution guides.
  - CI with lint, format, clippy, tests and `cargo audit`.

## 0.1.0

First version.

- **KeePass vaults:** KDBX 4 vaults with folders, tags, templates, attachments, history and TOTP.
- **Password tools:** generator and password health.
- **Typing and search:** Auto-Type, quick access, command palette and tray.
- **Integrations:**
  - KeePassXC-Browser extension, including passkeys.
  - SSH agent and KeeShare.
  - Windows Hello quick unlock.
- **Vaultwarden:** accounts as vaults, with two-way sync to a `.kdbx`.
- **Import:** from Bitwarden, 1Password, Proton Pass and KeePassXC.
