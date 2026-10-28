#!/bin/sh
set -eu
file="${NICK_FIXTURE_ROOT:?}/decoded.sh"
trap 'rm -f "$file"' EXIT
printf 'OiAjIGhhcm1sZXNzIE5pY2sgc2NvcmVjYXJkIHBheWxvYWQK' | /usr/bin/base64 -D > "$file"
/bin/sh "$file"
printf 'OiAjIGhhcm1sZXNzIE5pY2sgc2NvcmVjYXJkIHBpcGUgcGF5bG9hZAo=' \
  | /usr/bin/base64 -D \
  | /bin/sh
