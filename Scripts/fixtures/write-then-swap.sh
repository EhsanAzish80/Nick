#!/bin/sh
set -eu
root="${HOME}/Documents/NickScorecard"
mkdir -p "$root"
trap 'rm -rf "$root"' EXIT
i=1
while [ "$i" -le 200 ]; do
  target="$root/document-$i.txt"
  printf 'original document %s\n' "$i" > "$target"
  i=$((i + 1))
done
i=1
while [ "$i" -le 200 ]; do
  target="$root/document-$i.txt"
  temp="$root/.document-$i.tmp"
  /usr/bin/openssl rand 2048 > "$temp"
  /bin/mv -f "$temp" "$target.locked"
  /bin/rm -f "$target"
  i=$((i + 1))
done
printf '%s\n' 'NICK SCORECARD FIXTURE: harmless ransomware-detection test files.' > "$root/README_RESTORE_FILES.txt"
sleep 1
