#!/bin/sh
set -eu
file="${NICK_FIXTURE_ROOT:?}/Chrome/Default/Login Data"
mkdir -p "$(dirname "$file")"
trap 'rm -rf "${NICK_FIXTURE_ROOT:?}/Chrome"' EXIT
printf 'SQLite format 3\000synthetic-only' > "$file"
/bin/cat "$file" >/dev/null
