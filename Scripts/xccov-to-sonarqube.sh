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

printf '%s\n' '<coverage version="1">'

xcrun xccov view --archive "$1" |
awk '
  function close_file() {
    if (file_open) {
      print "  </file>"
      file_open = 0
    }
  }

  /^[^[:space:]].*:$/ {
    close_file()
    path = substr($0, 1, length($0) - 1)
    gsub(/&/, "\\&amp;", path)
    gsub(/</, "\\&lt;", path)
    gsub(/>/, "\\&gt;", path)
    gsub(/"/, "\\&quot;", path)
    printf "  <file path=\"%s\">\n", path
    file_open = 1
    next
  }

  /^[[:space:]]*[0-9]+:[[:space:]]+0([[:space:]]|$)/ {
    line = $1
    sub(/:$/, "", line)
    printf "    <lineToCover lineNumber=\"%s\" covered=\"false\"/>\n", line
    next
  }

  /^[[:space:]]*[0-9]+:[[:space:]]+[1-9][0-9]*([[:space:]]|$)/ {
    line = $1
    sub(/:$/, "", line)
    printf "    <lineToCover lineNumber=\"%s\" covered=\"true\"/>\n", line
    next
  }

  END {
    close_file()
  }
'

printf '%s\n' '</coverage>'
