#!/bin/sh
set -eu
backup="${NICK_FIXTURE_ROOT:?}/crontab.backup"
had_crontab=0
if crontab -l > "$backup" 2>/dev/null; then had_crontab=1; else : > "$backup"; fi
trap 'if [ "$had_crontab" -eq 1 ]; then crontab "$backup"; else crontab -r >/dev/null 2>&1 || true; fi' EXIT
{ cat "$backup"; printf '17 4 * * * /usr/bin/true # Nick scorecard\n'; } | crontab -
sleep 1
