#!/bin/zsh
set -euo pipefail

# Real-timing, installed-build proof. The local server returns only a shell
# no-op; no remote content is downloaded or executed.
incidents='/Library/Application Support/com.ehsanazish.nick/state/incidents.json'
work="$(mktemp -d /private/tmp/nick-pipeline.XXXXXX)"
server_pid=''
trap '[[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null || true; rm -rf "$work"' EXIT

count_findings() {
  sudo /usr/bin/python3 -c '
import json, sys
value = json.load(open(sys.argv[1]))
def walk(node):
    if isinstance(node, dict):
        return int(node.get("reason") == "download_pipe_interpreter") + sum(walk(v) for v in node.values())
    if isinstance(node, list):
        return sum(walk(v) for v in node)
    return 0
print(walk(value))
' "$incidents"
}

before="$(count_findings 2>/dev/null || echo 0)"
/bin/cp /usr/bin/curl "$work/network-reader"

/usr/bin/python3 -c '
import http.server, socketserver, sys, time
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(0.4)
        body = b": nick-safe-pipeline-fixture\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args): pass
with socketserver.TCPServer(("127.0.0.1", int(sys.argv[1])), Handler) as server:
    server.handle_request()
' 18765 &
server_pid=$!
sleep 0.1

echo 'DECLARED VALIDATION: renamed network reader -> zsh; local no-op payload only'
"$work/network-reader" -sS http://127.0.0.1:18765/fixture | /bin/zsh
wait "$server_pid"
server_pid=''

for _ in {1..30}; do
  sleep 0.2
  after="$(count_findings 2>/dev/null || echo 0)"
  if (( after > before )); then
    echo 'PASS: generic download-to-interpreter finding persisted'
    exit 0
  fi
done

echo "FAIL: download_pipe_interpreter count stayed at ${before}"
exit 1
