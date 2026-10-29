#!/bin/zsh
set -euo pipefail

script_dir=${0:A:h}
marker="$script_dir/canary_marker.txt"
temporary=$(mktemp "$HOME/.nick-canary-file.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT

cp -- "$marker" "$temporary"
cat -- "$temporary" >/dev/null
shasum -a 256 "$temporary" | awk '{print $1}'
rm -f -- "$temporary"
trap - EXIT
