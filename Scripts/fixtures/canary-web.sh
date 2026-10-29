#!/bin/zsh
set -euo pipefail

http_status=$(curl -sS --max-time 10 -o /dev/null -w '%{http_code}' \
    https://nick-canary.3nsofts.com/)
printf '%s\n' "$http_status"
