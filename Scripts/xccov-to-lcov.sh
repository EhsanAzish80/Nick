#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 || "$1" != *.xcresult || ! -d "$1" ]]; then
  echo "usage: $0 path/to/TestResults.xcresult" >&2
  exit 64
fi

command -v xcrun >/dev/null 2>&1 || {
  echo "xcrun is required" >&2
  exit 69
}

xcrun xccov view --archive "$1" |
awk '
  function close_file() {
    if (file_open) {
      print "end_of_record"
      file_open = 0
    }
  }

  /^[^[:space:]].*:$/ {
    close_file()
    path = substr($0, 1, length($0) - 1)
    skip_file = path ~ /\/NickTests\// || path ~ /\/NickIntegrationTests\//
    if (skip_file) {
      next
    }
    print "SF:" path
    file_open = 1
    next
  }

  /^[[:space:]]*[0-9]+:[[:space:]]+[0-9]+([[:space:]]|$)/ {
    if (skip_file) {
      next
    }
    line = $1
    sub(/:$/, "", line)
    count = $2
    printf "DA:%s,%s\n", line, count
  }

  END {
    close_file()
  }
'
