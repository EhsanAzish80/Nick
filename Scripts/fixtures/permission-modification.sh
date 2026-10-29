#!/bin/sh
set -eu
file="${NICK_FIXTURE_ROOT:?}/permission-fixture"
trap 'rm -f "$file"' EXIT
printf 'synthetic\n' > "$file"
chmod 600 "$file"
chmod 4777 "$file"
