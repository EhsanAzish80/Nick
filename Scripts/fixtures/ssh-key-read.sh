#!/bin/sh
set -eu
file="${NICK_FIXTURE_ROOT:?}/.ssh/id_scorecard"
mkdir -p "$(dirname "$file")"
trap 'rm -rf "${NICK_FIXTURE_ROOT:?}/.ssh"' EXIT
printf '%s\n' '-----BEGIN OPENSSH PRIVATE KEY-----' 'synthetic-not-a-key' '-----END OPENSSH PRIVATE KEY-----' > "$file"
/bin/cat "$file" >/dev/null
