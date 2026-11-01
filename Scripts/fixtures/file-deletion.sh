#!/bin/sh
set -eu

fixture_name="com.ehsanazish.nick.fixture.deletion.plist"
invoking_user="${NICK_FIXTURE_USER:-${SUDO_USER:-$(id -un)}}"
user_home="${NICK_FIXTURE_HOME:-$(/usr/bin/env NICK_FIXTURE_USER="$invoking_user" /usr/bin/python3 -c \
    'import os, pwd; print(pwd.getpwnam(os.environ["NICK_FIXTURE_USER"]).pw_dir)' 2>/dev/null || true)}"

if [ -z "$user_home" ]; then
    echo "Could not resolve the invoking user's home directory." >&2
    exit 65
fi

launch_agents="$user_home/Library/LaunchAgents"
plist="$launch_agents/$fixture_name"
phase2_marker="${NICK_FIXTURE_ROOT:?NICK_FIXTURE_ROOT is required}/file-deletion-phase2"

if [ "$(id -u)" -eq 0 ]; then
    echo "This fixture must run as the invoking user, never as root." >&2
    exit 77
fi

if [ -e "$plist" ]; then
    echo "Refusing to replace existing fixture path: $plist" >&2
    exit 73
fi

cleanup() {
    rm -f -- "$plist"
}
trap cleanup EXIT HUP INT TERM

if [ ! -d "$launch_agents" ] && ! mkdir -p "$launch_agents"; then
    echo "Could not create $launch_agents as $invoking_user; skipping file-deletion fixture." >&2
    exit 78
fi
umask 077
/usr/bin/plutil -create xml1 "$plist"
/usr/libexec/PlistBuddy -c "Add :Label string com.ehsanazish.nick.fixture.deletion" "$plist"
/usr/libexec/PlistBuddy -c "Add :ProgramArguments array" "$plist"
/usr/libexec/PlistBuddy -c "Add :ProgramArguments:0 string /usr/bin/true" "$plist"

# The root recorder observes the durable creation evidence, then creates the
# phase marker. The fixture itself never reads Nick's root-owned stores.
attempt=0
while [ "$attempt" -lt 35 ]; do
    if [ -e "$phase2_marker" ]; then
        rm -f -- "$plist"
        exit 0
    fi
    attempt=$((attempt + 1))
    sleep 1
done

echo "Recorder did not start deletion phase within 35 seconds; fixture cleaned up." >&2
exit 75
