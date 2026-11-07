#!/bin/sh
set -eu
fixture_root="${NICK_FIXTURE_ROOT:?NICK_FIXTURE_ROOT is required}"
source_file="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/helpers/credential-store-reader.c"
reader="$fixture_root/credential-store-reader"
file="$fixture_root/.ssh/id_nick_scorecard"
umask 077
mkdir -p "$fixture_root/.ssh"
printf '%s\n' '-----BEGIN OPENSSH PRIVATE KEY-----' 'synthetic-not-a-key' '-----END OPENSSH PRIVATE KEY-----' > "$file"
/usr/bin/xcrun clang -Os "$source_file" -o "$reader"
"$reader" "$file"
