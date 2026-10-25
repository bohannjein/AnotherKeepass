# Architecture

AnotherKeepass is a Tauri 2 app: a Rust process owns all vault data and secrets, a WebView
(React) shows the UI. Every Rust and TypeScript file starts with a short header comment
saying what it is for; this page is the map.

## Processes

```
browser extension ─ native messaging ─ anotherkeepass.exe --proxy ─┐
(KeePassXC-Browser)                    (proxy.rs)                  │ named pipe / socket
                                                                   ▼
WebView (React UI) ── Tauri commands ──► Rust main process ◄── SSH clients (ssh.rs, pipe)
                    ◄─ events ─────────  (vaults, crypto, tray, Auto-Type)
```

- The **UI never holds the vault**. It gets lists of entries without secrets (`VaultDto`).
  It asks for a password only to show or edit it, and copying goes Rust → clipboard
  directly.
- **Browser requests** are encrypted (NaCl box) and need a stored association. The UI only
  answers confirmations (`browser_server.rs` ↔ `BrowserAskDialog`).

## Data flow

```
.kdbx file ──┐
             ├─► OpenVault (keepass::Database in memory) ─► VaultDto ─► UI model (model.ts)
Vaultwarden ─┘    vault/mod.rs                              vault/mod.rs   backend.ts
account           bitwarden/ decrypts the account into the same Database type
```

A Vaultwarden account becomes an ordinary `keepass::Database` in memory. Because of that,
list, search, Auto-Type, browser, passkeys and health work the same for both. Saving
writes the file (`write_db`); for an account, only the changed items go to the server.
`sync.rs` links a `.kdbx` with an account (two-way, newer change wins).

## Rust (`src-tauri/src`)

| Module | Purpose |
|---|---|
| `lib.rs` | Starts the app: plugins, state, command list, tray, windows |
| `vault/` | Open vaults. `mod.rs` core and DTOs, `open.rs` lifecycle and Windows Hello, `entries.rs` entry/folder commands, `settings.rs`, `watch.rs` reload on external changes |
| `bitwarden/` | Vaultwarden: `crypto.rs` keys and EncStrings, `api.rs` HTTP, `mapping.rs` cipher ↔ entry |
| `sync.rs` | Two-way sync of a `.kdbx` and an account |
| `browser/` | KeePassXC-Browser protocol: `mod.rs` session and dispatch, `actions.rs` logins/save/TOTP/groups, `webauthn.rs` passkeys |
| `browser_server.rs`, `proxy.rs` | Pipe server for the extension, native-messaging proxy mode |
| `passkeys.rs` | WebAuthn software authenticator (signing, attestation) |
| `autotype.rs`, `quick.rs` | Auto-Type and the quick-access window |
| `desktop.rs` | Tray, autostart, window behaviour, locking on Windows events, screen-capture protection |
| `hardening.rs` | Process hardening, DPAPI, pipe owner checks |
| `ssh.rs`, `keeshare.rs`, `health.rs`, `favicon.rs`, `clipboard.rs`, `hello.rs`, `transfer.rs`, `update.rs` | One feature each, see the file header |

## Frontend (`src`)

| File | Purpose |
|---|---|
| `main.tsx` | Picks the main app or the quick window (`?quick=1` → `QuickApp.tsx`) |
| `App.tsx` | App state and layout: vault list, entry list, navigation, all actions |
| `Detail.tsx` | Entry view and edit form |
| `ItemList.tsx`, `Dialogs.tsx`, `Setup.tsx` | List rows, small dialogs, first start |
| `*Dialog.tsx`, `SettingsPage.tsx`, `HealthOverview.tsx`, `CommandPalette.tsx` | One view each |
| `backend.ts` | All calls into Rust. Its browser variant (`mock.ts`) is the demo for `npm run dev` |
| `model.ts` | UI model ↔ KDBX mapping |
| `importers.ts`, `generator.ts`, `totp.ts`, `listGroups.ts` | Pure logic, each with a `*.check.ts` |
| `i18n.ts`, `i18n-settings.ts` | Texts in en/de/fr/es |
| `settings.ts` | One schema for defaults, the settings page and import validation |

## Security model

- Secrets stay in Rust. Protected values are zeroized when a vault locks.
- `hardening.rs` applies these protections at start:
  - Other processes of the same user cannot read our memory (process DACL).
  - DLLs load only from safe folders.
  - Crash reports contain no heap memory.
  - For troubleshooting, `AKP_NO_HARDENING=1` turns these off.
- The browser and SSH pipes are owner-only. The proxy checks that the pipe server is ours.
- Account data on disk is protected with Windows DPAPI. Master passwords are never stored.
- Not protected: the WebView itself. Anything shown on screen is in its memory while it is
  shown.

## Where to start

- **New field type or item type**: edit `model.ts` (mapping) and `Detail.tsx` (UI). If it has
  to survive in Vaultwarden, also edit `bitwarden/mapping.rs`.
- **New language**: add a block to `i18n.ts` and to `i18n-settings.ts`, then add the language
  to `LANGS`.
- **New import format**: add a parser function in `importers.ts` and a case in
  `importers.check.ts`.
- **New setting**: add it to `settings.ts`. If Rust needs it, also add it to `DesktopPrefs` in
  `desktop.rs`.
- **New Tauri command**: write the function in the matching Rust module, register it in
  `lib.rs`, and add the wrapper in `backend.ts`.
