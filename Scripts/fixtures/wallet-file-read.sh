#!/bin/sh
set -eu
file="${HOME:?}/Library/Passes/NickScorecard/pass.pkpass"
mkdir -p "$(dirname "$file")"
trap 'rm -rf "${HOME:?}/Library/Passes/NickScorecard"' EXIT
printf 'synthetic wallet fixture; no credentials\n' > "$file"
/bin/cat "$file" >/dev/null
