#!/bin/sh
set -eu
fixture_root="${NICK_FIXTURE_ROOT:?NICK_FIXTURE_ROOT is required}"
source_file="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/helpers/credential-store-reader.c"
reader="$fixture_root/credential-store-reader"
file="${HOME:?}/Library/Application Support/Chromium/NickScorecard/Login Data"
mkdir -p "$(dirname "$file")"
trap 'rm -rf "${HOME:?}/Library/Application Support/Chromium/NickScorecard"' EXIT
printf 'SQLite format 3\000synthetic-only' > "$file"
/usr/bin/xcrun clang -Os "$source_file" -o "$reader"
"$reader" "$file"
