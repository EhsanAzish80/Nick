#!/bin/sh
set -eu
file="${HOME:?}/Library/Application Support/Google/Chrome/NickScorecard/Login Data"
mkdir -p "$(dirname "$file")"
trap 'rm -rf "${HOME:?}/Library/Application Support/Google/Chrome/NickScorecard"' EXIT
printf 'SQLite format 3\000synthetic-only' > "$file"
/bin/cat "$file" >/dev/null
