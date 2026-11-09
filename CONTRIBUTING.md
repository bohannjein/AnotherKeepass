# Contributing

Thanks for helping. AnotherKeepass is a password manager, so two things matter most: other
people must be able to read the code, and it must stay small.

## Before you open a pull request

```bash
npm run check                      # types, lint, frontend self-checks
cd src-tauri
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test --lib
cargo audit
```

CI (`.github/workflows/check.yml`) runs the same commands on Windows, and clippy and the tests
on Linux too. A red check means no merge.

Browser integration end to end (real named pipe, needs Node):

```bash
cd src-tauri && cargo test --lib browser_pipe_e2e -- --ignored
```

To narrow down a crash or a hang, start the app with `AKP_NO_HARDENING=1`: the process
hardening (`src-tauri/src/hardening.rs`) stays off. The log is in
`%LOCALAPPDATA%\app.anotherkeepass.desktop\logs\anotherkeepass.log`.

## House rules

- **Read [ARCHITECTURE.md](ARCHITECTURE.md) first.** It says where things live.
- **Small modules.** If a file grows past ~800 lines, split it by topic before adding more.
- **No new dependency without a reason.** Use the standard library or a crate that is already
  in `Cargo.toml` / `package.json` when it can do the job. Say why in the PR when you add one.
- **Every logic change comes with a test.** Rust: `#[test]` in the same file. Frontend: a pure
  function plus a `*.check.ts` script (see `src/listGroups.check.ts`). Add the script to the
  `check` script in `package.json`.
- **Comments explain why, not what.** Every module starts with a `//!` (Rust) or `//` (TS)
  header that says what it is for.
- **English in code, UI text only through i18n.** Add the key to all four languages in
  `src/i18n.ts` or `src/i18n-settings.ts`. The type system shows a missing language.
- **The `.kdbx` stays compatible.** Data that KeePassXC does not know goes into entry
  custom data `AnotherKeepass.*`. Test with `keepassxc-cli` (see README).
- **Secrets stay in Rust.** The UI only gets protected values to show or edit them.
- **Security reports:** please do not open a public issue. Contact the maintainer privately
  first.

## Releases (maintainers)

1. Raise the version in `package.json`, `src-tauri/Cargo.toml` and `src-tauri/tauri.conf.json`.
2. Rename `## Unreleased` in `CHANGELOG.md` to the version, commit and push.
3. Tag and push: `git tag -a v1.2.3 -m "AnotherKeepass 1.2.3"`, then `git push origin v1.2.3`.
   A tag with a hyphen (`v1.2.3-beta.1`) becomes a pre-release.
4. `.github/workflows/build.yml` builds Windows (NSIS) and Linux (AppImage), signs the update
   packages and creates a **draft** release (about 10 minutes). It needs the repository secret
   `TAURI_SIGNING_PRIVATE_KEY`, the full content of the update key file.
5. Check the draft: `.exe` and `.AppImage`, each with a `.sig`, and `latest.json`. Then publish
   it; installed apps only see the update after that.

## Microsoft Store (MSIX)

The release workflow also packs the Windows build as `AnotherKeepass_<version>_x64.msix`
(`msix/AppxManifest.xml`, `scripts/build-msix.mjs`). It is unsigned; the Store signs it.

1. In Partner Center reserve the name and open *Product management > Product identity*.
2. Add three repository variables (Settings > Secrets and variables > Actions > Variables):
   `MSIX_IDENTITY_NAME` (Package/Identity/Name), `MSIX_PUBLISHER` (Package/Identity/Publisher,
   starts with `CN=`) and `MSIX_PUBLISHER_NAME` (Package/Properties/PublisherDisplayName).
3. Make a release as above, then upload the `.msix` from the release to the Store submission.
4. The package asks for two restricted capabilities. Explain them in the submission:
   `runFullTrust` (a desktop app) and `unvirtualizedResources` (the browser integration writes
   native messaging manifests and registry keys that Chrome, Edge and Firefox must see).

Inside the package the app turns its own updater off (the Store updates it), uses the
package's StartupTask for "Open at login" and points browsers to its app execution alias.

## License

By contributing you agree that your work is published under the
[GPL-3.0-or-later](LICENSE), like the rest of the project.
