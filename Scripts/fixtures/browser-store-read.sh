#!/bin/sh
set -eu
fixture_root="${NICK_FIXTURE_ROOT:?NICK_FIXTURE_ROOT is required}"
source_file="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/helpers/credential-store-reader.c"
reader="$fixture_root/credential-store-reader"
file="$fixture_root/Login Data"
umask 077
printf 'SQLite format 3\000synthetic-only' > "$file"
/usr/bin/xcrun clang -Os "$source_file" -o "$reader"
"$reader" "$file"
