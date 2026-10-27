#!/bin/sh
set -eu
file="${NICK_FIXTURE_ROOT:?}/downloaded-fixture.sh"
trap 'rm -f "$file"' EXIT
printf '#!/bin/sh\nexit 0\n' > "$file"
chmod 700 "$file"
xattr -w com.apple.quarantine '0081;00000000;NickScorecard;' "$file"
"$file"
