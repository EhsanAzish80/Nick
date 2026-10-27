#!/bin/sh
set -eu
root="${NICK_FIXTURE_ROOT:?}"
printf ': # harmless Nick scorecard payload\n' > "$root/payload"
python3 -m http.server 18765 --bind 127.0.0.1 --directory "$root" >/dev/null 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true; rm -f "$root/payload"' EXIT
sleep 1
python3 -c 'import sys,urllib.request;sys.stdout.buffer.write(urllib.request.urlopen(sys.argv[1]).read())' http://127.0.0.1:18765/payload | /bin/sh
