#!/bin/sh
set -eu
file="${HOME:?}/.ssh/id_nick_scorecard"
mkdir -p "$(dirname "$file")"
trap 'rm -f "$file"' EXIT
printf '%s\n' '-----BEGIN OPENSSH PRIVATE KEY-----' 'synthetic-not-a-key' '-----END OPENSSH PRIVATE KEY-----' > "$file"
/bin/cat "$file" >/dev/null
