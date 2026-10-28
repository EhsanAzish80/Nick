#!/bin/sh
set -eu
root="${HOME}/Downloads/NickScorecard"
file="$root/eicar.com"
mkdir -p "$root"
trap 'rm -f "$file"; rmdir "$root" 2>/dev/null || true' EXIT
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$file"
/usr/bin/xattr -w com.apple.quarantine '0081;00000000;NickScorecard;' "$file"
/bin/cat "$file" >/dev/null
sleep 2
