#!/bin/sh
set -eu
file="${NICK_FIXTURE_ROOT:?}/Wallet/pass.pkpass"
mkdir -p "$(dirname "$file")"
trap 'rm -rf "${NICK_FIXTURE_ROOT:?}/Wallet"' EXIT
printf 'synthetic wallet fixture; no credentials\n' > "$file"
/bin/cat "$file" >/dev/null
