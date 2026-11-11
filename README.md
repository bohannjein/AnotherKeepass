# AnotherKeepass

KeePass-compatible desktop password manager (KDBX 4) with a Material 3 Expressive UI.
Tauri 2 + Rust (`keepass` crate) + React/TypeScript.

Your vaults stay ordinary `.kdbx` files that KeePassXC, KeePass2 and KeePassDX open too.

- Several vaults at once, folders, tags, pinned items, templates, attachments, history
- TOTP, password generator, password health (weak / reused / old / breached)
- Search with KeePassXC-style operators (`user:`, `url:`, `tag:`, `is:weak`, `-exclude`, …)
- Eight color schemes plus your own, light / dark / OLED / follow the system; resizable columns
- Auto-Type, quick-access window (Ctrl+Alt+K), command palette (Ctrl+K), tray
- Browser extension: works with the KeePassXC-Browser extension, including passkeys
- SSH agent (KeeAgent compatible), KeeShare, Windows Hello quick unlock, YubiKey challenge-response
- Vaultwarden accounts as vaults, two-way sync between a `.kdbx` and an account
- Import from Bitwarden, 1Password, Proton Pass and KeePassXC CSV

How the code is organised: [ARCHITECTURE.md](ARCHITECTURE.md). How to contribute:
[CONTRIBUTING.md](CONTRIBUTING.md). License: [GPL-3.0-or-later](LICENSE).

## Develop

```bash
npm install
npm run dev          # browser preview with in-memory demo vaults (any password)
npx tauri dev        # desktop app with real .kdbx files
```

## Install and update

Download the installer from the [releases](https://github.com/johann-beinsen/AnotherKeepass/releases).
The app updates itself: it checks at start and once a day, downloads in the background and
installs on a click (or on its own while idle in the tray). An update is installed only if
it carries the project's update signature (minisign, public key in `src-tauri/tauri.conf.json`).

Releases are built by GitHub Actions from the tagged source (`.github/workflows/build.yml`).
Windows code signing (SignPath Foundation) is being set up; until then Windows may warn about an
unknown publisher, and Microsoft Defender's ML scanner may flag a fresh build.

Making a release: see [CONTRIBUTING.md](CONTRIBUTING.md#releases-maintainers).

## Build

```bash
npx tauri build --bundles nsis       # Windows: exe + installer
npx tauri build --bundles appimage   # Linux (or use .github/workflows/build.yml)
```

## Tests

```bash
npx tsc -b
node src/totp.check.ts
node src/generator.check.ts
node src/model.check.ts
node src/importers.check.ts
node src/listGroups.check.ts
cd src-tauri && cargo test --lib
cargo test --lib browser_pipe_e2e -- --ignored   # browser protocol over a real pipe, tweetnacl client
```

Browser integration: AnotherKeepass serves the same local socket as KeePassXC, so the
KeePassXC-Browser extension works through an installed `keepassxc-proxy`. KeePassXC itself
must not run at the same time. Without KeePassXC, enable "Update native messaging manifests"
and the exe registers itself as proxy.

KeePassXC compatibility (needs `keepassxc-cli`, run by hand):

```bash
# 1. we write, KeePassXC reads
AKP_COMPAT_DIR=/tmp/akp cargo test --lib compat_write -- --ignored
echo compat-pw | keepassxc-cli show -s -t /tmp/akp/ours.kdbx Work/Mail
# 2. KeePassXC writes, we edit, KeePassXC reads
keepassxc-cli db-create -p /tmp/akp/theirs.kdbx            # password: compat-pw
keepassxc-cli add -u alice -p /tmp/akp/theirs.kdbx Mail
AKP_COMPAT_DIR=/tmp/akp cargo test --lib compat_edit -- --ignored
echo compat-pw | keepassxc-cli show -s /tmp/akp/theirs.kdbx "Mail edited"
```

## How data maps to KDBX

| UI | KDBX |
|---|---|
| Vault | one `.kdbx` file |
| Folder | group (Recycle Bin = KeePass recycle bin) |
| Title / username / password / website / note | standard strings |
| Custom fields, card, identity | custom strings (hidden/TOTP = protected) |
| TOTP | `otp` string (`otpauth://`, KeePassXC format) |
| Pinned | tag `pinned` |
| Item type, field kinds | entry custom data `AnotherKeepass.*` |
| Attachments, expiry, history | native KDBX features |

KDBX 3.1 files are read; on first save they are upgraded to KDBX 4 (like KeePassXC)
and the original is kept as `<file>.kdbx3-backup`.

Secrets stay in the Rust process: the UI fetches protected values only to show or edit
them, and copying goes straight to the clipboard (excluded from Windows clipboard history,
cleared after the configured time only if unchanged).

## Roadmap

Done: KDBX core, entry lifecycle, desktop integration, browser integration, Vaultwarden,
import, hardening, auto-update, YubiKey.

### Before 1.0 (Windows release)

Priority order; these are real gaps.

1. **Test the fixes in the real app** (MSIX): master key change with key file and with
   YubiKey, browser approval dialogs (arming delay, queue), lock with a failed save, text
   selection, focus ring and corner radii in the native window. A bug in the key change can
   lock a vault, so this blocks everything else.
2. **Signing and distribution:** the MSIX is unsigned and uses the test identity
   `AnotherKeepass.Test`. Choose a route (Store or own certificate), set the real identity
   and publisher in the build, and run the update path end to end once.
3. **Verify Vaultwarden against a real server:** the fix for lost server-only fields is only
   tested against the mock server. Edit items with passkeys, several URIs and attachments on
   a test account and compare on the server.
4. **Linux:** either test it (CI on the branch, then browser integration and Auto-Type on a
   real Linux system; the new socket permission code has only been compiled in CI) or label
   it a preview in 1.0.
5. **Failed save on lock:** locking proceeds and the change stays in `<file>.unsaved.kdbx`.
   Check that the app notices this file on the next open and offers to merge it; add that if
   it is missing.
6. **Release hygiene:** commit the open changes, add the fixes to the CHANGELOG, point
   `origin` at `johann-beinsen`, bring the branch into `main`, bump the version.

### Optional (can follow after 1.0)

- macOS: active window for Auto-Type, native messaging manifests, screen lock signals.
  For 1.0, "Windows only, Linux as preview" is enough if documented.
- Secret Service on Linux for the "remember 2FA" token (without DPAPI it is not stored now).
- An own browser extension (Manifest V3); the KeePassXC extension works today.
- Settings marked "planned" (custom browser path on Linux/macOS): implement or hide them.
- The exe (NSIS) installer stays as it is.
