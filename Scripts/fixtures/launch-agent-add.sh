#!/bin/sh
set -eu
user_home="${HOME:?}"
mkdir -p "$user_home/Library/LaunchAgents"
plist="$user_home/Library/LaunchAgents/com.3nsofts.nick.scorecard.plist"
trap 'launchctl bootout "gui/$(id -u)" "$plist" >/dev/null 2>&1 || true; rm -f "$plist"' EXIT
printf '%s\n' '<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>com.3nsofts.nick.scorecard</string><key>ProgramArguments</key><array><string>/usr/bin/true</string></array></dict></plist>' > "$plist"
launchctl bootstrap "gui/$(id -u)" "$plist" >/dev/null 2>&1 || true
sleep 1
