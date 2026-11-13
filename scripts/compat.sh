#!/usr/bin/env bash
# KeePassXC compatibility in both directions (needs keepassxc-cli). Run from the repo root:
#   bash scripts/compat.sh
# 1. we write a vault, KeePassXC reads it   2. KeePassXC writes one, we edit it, KeePassXC reads it
set -euo pipefail
export QT_QPA_PLATFORM=offscreen
dir=$(mktemp -d)
export AKP_COMPAT_DIR="$dir"
pw=compat-pw
expect() { grep -qE "$2" <<<"$1" || { echo "missing: $2"; echo "$1"; exit 1; }; }

(cd src-tauri && cargo test --lib compat_write -- --ignored)
out=$(echo "$pw" | keepassxc-cli show -q -s "$dir/ours.kdbx" Work/Mail 2>/dev/null)
expect "$out" '^UserName: bob$'
expect "$out" '^Password: s3cret-Pa55$'
expect "$out" '^URL: https://example.org$'
# older KeePassXC prints only the code with -t, so ask for it on its own
expect "$(echo "$pw" | keepassxc-cli show -q -t "$dir/ours.kdbx" Work/Mail 2>/dev/null)" '^[0-9]{6}$'
echo "$pw" | keepassxc-cli show -q -s -a "Card number" "$dir/ours.kdbx" Work/Mail 2>/dev/null | grep -qx 4111

printf '%s\n%s\n' "$pw" "$pw" | keepassxc-cli db-create -q -p "$dir/theirs.kdbx"
echo "$pw" | keepassxc-cli add -q -u alice -g "$dir/theirs.kdbx" Mail
before=$(echo "$pw" | keepassxc-cli show -q -s -a Password "$dir/theirs.kdbx" Mail)
(cd src-tauri && cargo test --lib compat_edit -- --ignored)
out=$(echo "$pw" | keepassxc-cli show -q -s "$dir/theirs.kdbx" "Mail edited")
expect "$out" '^UserName: alice$'
after=$(echo "$pw" | keepassxc-cli show -q -s -a Password "$dir/theirs.kdbx" "Mail edited")
[ -n "$before" ] && [ "$before" = "$after" ] || { echo "password changed by our edit"; exit 1; }

rm -rf "$dir"
echo "KeePassXC compatibility: ok ($(keepassxc-cli --version))"
