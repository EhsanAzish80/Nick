#!/bin/sh
set -eu
root="${NICK_FIXTURE_ROOT:?}"
mkdir -p "$root/Library/LaunchAgents"
plist="$root/Library/LaunchAgents/com.3nsofts.nick.scorecard.plist"
trap 'rm -f "$plist"' EXIT
printf '%s\n' '<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>com.3nsofts.nick.scorecard</string><key>ProgramArguments</key><array><string>/usr/bin/true</string></array></dict></plist>' > "$plist"
sleep 1
