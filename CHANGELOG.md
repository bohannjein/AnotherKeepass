# Changelog

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
