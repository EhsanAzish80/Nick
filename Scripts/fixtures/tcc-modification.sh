#!/bin/sh
set -eu

root="${NICK_FIXTURE_ROOT:?}"
app="$root/Nick TCC Fixture.app"
identifier="com.3nsofts.nicktcc"

/usr/bin/osacompile -o "$app" -e 'tell application "Finder" to get name of startup disk'
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $identifier" "$app/Contents/Info.plist" 2>/dev/null \
  || /usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string $identifier" "$app/Contents/Info.plist"
/usr/bin/codesign --force --sign - "$app"

echo "Opening a bundled test applet ($identifier). Click Allow once in the Apple Events prompt."
echo "Unbundled AppleScript applets may appear in macOS UI only as 'applet'; this fixture uses an explicit bundle ID."
/usr/bin/open "$app"
printf 'Press Return after clicking Allow: '
IFS= read -r _
/usr/bin/tccutil reset AppleEvents "$identifier"
echo "Reset AppleEvents permission for $identifier; waiting for Nick to persist the TCC change."
sleep 3
