# AnotherKeepass

KeePass-compatible desktop password manager (KDBX 4) with a Material 3 Expressive UI.
Tauri 2 + Rust (`keepass` crate) + React/TypeScript.

Your vaults stay ordinary `.kdbx` files that KeePassXC, KeePass2 and KeePassDX open too.

- Several vaults at once, folders, tags, pinned items, templates, attachments, history
- TOTP, password generator, password health (weak / reused / old / breached)
- Auto-Type, quick-access window (Ctrl+Alt+K), command palette (Ctrl+K), tray
- Browser extension: works with the KeePassXC-Browser extension, including passkeys
- SSH agent (KeeAgent compatible), KeeShare, Windows Hello quick unlock
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

Download the installer from the [releases](https://github.com/bohannjein/AnotherKeepass/releases).
The app updates itself: Settings checks GitHub weekly, and an update is installed only if
it carries the project's update signature (minisign, public key in `src-tauri/tauri.conf.json`).

Releases are built by GitHub Actions from the tagged source (`.github/workflows/build.yml`).
Windows code signing (SignPath Foundation) is being set up; until then Windows may warn about an
unknown publisher, and Microsoft Defender's ML scanner may flag a fresh build.

Making a release: bump the version in `package.json`, `src-tauri/Cargo.toml` and
`src-tauri/tauri.conf.json`, add a `CHANGELOG.md` section, push a tag `vX.Y.Z`, check the
draft release on GitHub and publish it.

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
import, hardening. Next: signed releases with auto-update, Linux polish, and an own
browser extension (Manifest V3).
