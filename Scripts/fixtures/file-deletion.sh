#!/bin/sh
set -eu

fixture_name="com.ehsanazish.nick.fixture.deletion.plist"
invoking_user="${SUDO_USER:-$(id -un)}"
user_home="${NICK_FIXTURE_HOME:-$(/usr/bin/env NICK_FIXTURE_USER="$invoking_user" /usr/bin/python3 -c \
    'import os, pwd; print(pwd.getpwnam(os.environ["NICK_FIXTURE_USER"]).pw_dir)' 2>/dev/null || true)}"

if [ -z "$user_home" ]; then
    echo "Could not resolve the invoking user's home directory." >&2
    exit 65
fi

launch_agents="$user_home/Library/LaunchAgents"
plist="$launch_agents/$fixture_name"
baseline="${NICK_FIM_BASELINE_PATH:-/Library/Application Support/com.ehsanazish.nick/fim_baseline.json}"

if [ -e "$plist" ]; then
    echo "Refusing to replace existing fixture path: $plist" >&2
    exit 73
fi

cleanup() {
    rm -f -- "$plist"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$launch_agents"
umask 077
printf '%s\n' \
    '<?xml version="1.0" encoding="UTF-8"?>' \
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
    '<plist version="1.0"><dict>' \
    '<key>Label</key><string>com.ehsanazish.nick.fixture.deletion</string>' \
    '<key>ProgramArguments</key><array><string>/usr/bin/true</string></array>' \
    '</dict></plist>' > "$plist"

# Deletion is meaningful only after Nick has recorded this exact file in its
# integrity baseline. Bound the wait so a disconnected or stale monitor cannot
# leave the replay hanging indefinitely.
attempt=0
while [ "$attempt" -lt 30 ]; do
    if /usr/bin/python3 - "$baseline" "$plist" <<'PY'
import json
import pathlib
import sys

baseline = pathlib.Path(sys.argv[1])
target = sys.argv[2]
try:
    payload = json.loads(baseline.read_text(encoding="utf-8"))
except (OSError, ValueError):
    raise SystemExit(1)
entries = payload.get("entries", payload) if isinstance(payload, dict) else {}
raise SystemExit(0 if target in entries else 1)
PY
    then
        rm -f -- "$plist"
        # Give Endpoint Security time to deliver the deletion evidence; the
        # recorder independently waits for durable file_integrity_deleted.
        sleep 2
        exit 0
    fi
    attempt=$((attempt + 1))
    sleep 1
done

echo "Nick did not baseline the inert LaunchAgent within 30 seconds; deletion was not attempted." >&2
exit 75
