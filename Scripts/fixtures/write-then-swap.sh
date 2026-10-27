#!/bin/sh
set -eu
root="${NICK_FIXTURE_ROOT:?}/documents"
mkdir -p "$root"
trap 'rm -rf "$root"' EXIT
i=1
while [ "$i" -le 10 ]; do
  target="$root/document-$i.txt"
  temp="$root/.document-$i.tmp"
  printf 'original document %s\n' "$i" > "$target"
  /usr/bin/openssl rand 2048 > "$temp"
  /bin/mv -f "$temp" "$target.locked"
  /bin/rm -f "$target"
  i=$((i + 1))
done
sleep 1
