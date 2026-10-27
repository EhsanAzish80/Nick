#!/bin/sh
set -eu
file="${NICK_FIXTURE_ROOT:?}/.zshrc"
trap 'rm -f "$file"' EXIT
printf 'export NICK_SCORECARD_FIXTURE=1\n' > "$file"
sleep 1
