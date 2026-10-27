#!/bin/sh
set -eu
python3 -m http.server 18766 --bind 127.0.0.1 --directory "${NICK_FIXTURE_ROOT:?}" >/dev/null 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true' EXIT
sleep 1
/usr/bin/curl -fsS http://127.0.0.1:18766/ >/dev/null
