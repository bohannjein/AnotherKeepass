# Changelog

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
