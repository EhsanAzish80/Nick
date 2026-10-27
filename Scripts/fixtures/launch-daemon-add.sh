#!/bin/sh
set -eu
plist=/Library/LaunchDaemons/com.3nsofts.nick.scorecard.plist
trap 'launchctl bootout system "$plist" >/dev/null 2>&1 || true; rm -f "$plist"' EXIT
printf '%s\n' '<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>com.3nsofts.nick.scorecard</string><key>ProgramArguments</key><array><string>/usr/bin/true</string></array><key>RunAtLoad</key><false/></dict></plist>' > "$plist"
chmod 644 "$plist"
chown root:wheel "$plist"
launchctl bootstrap system "$plist" >/dev/null 2>&1 || true
sleep 1
