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

CI (`.github/workflows/check.yml`) runs the same commands. A red check means no merge.

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

## License

By contributing you agree that your work is published under the
[GPL-3.0-or-later](LICENSE), like the rest of the project.
