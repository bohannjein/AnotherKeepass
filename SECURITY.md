# Security

## Reporting a vulnerability

Please do not open a public issue for a security problem.

- Use GitHub's private reporting: **Security > Report a vulnerability** on
  [github.com/johann-beinsen/AnotherKeepass](https://github.com/johann-beinsen/AnotherKeepass/security/advisories/new), or
- write to **info@beinsen.eu**.

Say which version you use, what you did and what happened. You get an answer within a week.
A fix is released as soon as it is ready, and the reporter is named in the changelog unless
they prefer not to be.

## Supported versions

Only the newest release gets security fixes. The app updates itself (Store version: through
the Store), so this is the version most people run.

## What the app protects

- **The vault file** is a standard KDBX 4 file, encrypted by the `keepass` crate (AES-256 or
  ChaCha20, key derivation with Argon2). Nothing about it is special to this app; KeePassXC
  opens the same file. A file with weak key derivation settings is flagged in the app.
- **Secrets stay in the Rust part of the app.** The window (WebView) gets a list of entries
  without protected values; a password is sent to it only when you reveal or copy it.
  Protected values are zeroized when a vault locks.
- **Locking:** after inactivity, when Windows locks, or by hand. Locking and quitting wait until
  a queued save is written. If a save fails, the change is kept in `<file>.unsaved.kdbx` and
  merged back in when the vault opens next.
- **Saving** goes through a temporary file that is flushed to disk and then renamed over the
  vault, so a crash never leaves a half-written file. A change made by another program in the
  meantime (cloud sync, KeePassXC) is merged, never overwritten.
- **Clipboard:** copied secrets are kept out of Windows clipboard history and cloud sync and
  are cleared after a timeout, but only if the clipboard still holds what we put there.
- **Process hardening (Windows):** other programs of the same user cannot read our memory or
  inject code, DLLs load only from the app folder and System32, crash reports contain no heap
  memory. The window can be hidden from screenshots and screen sharing. Set
  `AKP_NO_HARDENING=1` to turn the hardening off when troubleshooting.
- **Browser and SSH agent** talk to the app through owner-only pipes. Each browser connection
  has to be approved once; the approval button stays disabled for a moment after the dialog
  appears, so that a click meant for another window cannot confirm it.
- **Account data** (Vaultwarden tokens) is encrypted with Windows DPAPI for your user.
  The master password is never stored. Windows Hello quick unlock keeps the key only in
  memory, never in a file; turning the option off or quitting forgets it.
- **Updates** are installed only if they carry the project's signature (minisign, public key in
  `src-tauri/tauri.conf.json`). Releases are built by GitHub Actions from the tagged source and
  come with SHA-256 sums.
- **Network:** no telemetry, no account. The app contacts the network only for what you turn
  on: update checks (GitHub), website icons, the breach check (the first 5 characters of a
  SHA-1 hash, never the password), and Vaultwarden accounts you add.

## What it does not protect against

- **Malware running as you, or with administrator rights.** It can read what is on screen,
  log keystrokes, and watch the clipboard. A password manager cannot fix a compromised
  computer.
- **Anything while a vault is unlocked and shown.** Revealed passwords are in the memory of
  the window for as long as they are shown.
- **Memory dumps, swap and hibernation files.** Secrets are zeroized when locking, but
  Windows may have written memory to disk earlier.
- **A weak master password.** Argon2 slows guessing down; it does not stop it.
- **Auto-Type and clipboard:** another program with focus, or one that reads the clipboard
  within the clear timeout, gets the text.
- **The unsigned Windows installer (exe):** until the code signature is in place, Windows
  SmartScreen warns about an unknown publisher. Check the SHA-256 sum on the download page
  or use the Store version.
- **Losing a YubiKey you rely on.** A vault protected by a YubiKey cannot be opened or saved
  without it. The app never writes to the key, so the secret on it cannot be recovered from
  here: keep a written copy of the secret or a second key set up with the same secret. The app
  tries the new key by opening the vault again after a key change, and puts the old key back if
  that fails.
- **Linux and YubiKey** are new and have not had a real-world test with hardware yet; they are
  marked as such in the README until they have. "Check YubiKey" in the dialogs tests a key and
  slot without changing anything.

## Third-party code

Dependencies are checked with `cargo audit` on every push. The app embeds Microsoft
WebView2 (Windows) or WebKitGTK (Linux), which are updated by the system.
