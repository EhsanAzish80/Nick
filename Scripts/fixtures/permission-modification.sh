#!/bin/sh
set -eu
file="${NICK_FIXTURE_ROOT:?}/permission-fixture"
trap 'rm -f "$file"' EXIT
printf 'synthetic\n' > "$file"
chmod 600 "$file"
# Keep this process observable, then preserve its PID across exec into chmod.
/bin/sh -c 'sleep 1; exec /bin/chmod 4777 "$1"' sh "$file"
