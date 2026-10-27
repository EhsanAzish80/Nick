#!/bin/sh
set -eu
file="${NICK_FIXTURE_ROOT:?}/eicar.com"
trap 'rm -f "$file"' EXIT
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$file"
sleep 2
