#!/bin/sh
set -eu
file="${HOME:?}/.zshrc"
backup="${NICK_FIXTURE_ROOT:?}/zshrc.backup"
had_file=0
if [ -f "$file" ]; then cp "$file" "$backup"; had_file=1; fi
trap 'if [ "$had_file" -eq 1 ]; then cp "$backup" "$file"; else rm -f "$file"; fi' EXIT
printf '\n# Nick scorecard reversible marker\nexport NICK_SCORECARD_FIXTURE=1\n' >> "$file"
sleep 10
