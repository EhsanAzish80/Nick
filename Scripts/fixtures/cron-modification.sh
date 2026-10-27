#!/bin/sh
set -eu
file="${NICK_FIXTURE_ROOT:?}/scorecard.crontab"
trap 'rm -f "$file"' EXIT
printf '17 4 * * * /usr/bin/true # Nick scorecard\n' > "$file"
sleep 1
