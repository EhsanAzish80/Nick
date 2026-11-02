#!/bin/sh
set -eu

home="${NICK_FIXTURE_HOME:?NICK_FIXTURE_HOME is required}"
container="$home/Applications/Nick Scorecard Fixtures"
app="$container/Nick TCC Fixture.app"
identifier="com.3nsofts.nicktcc"
lsregister="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

cleanup() {
  "$lsregister" -u "$app" >/dev/null 2>&1 || true
  case "$app" in
    "$home/Applications/Nick Scorecard Fixtures/Nick TCC Fixture.app") /bin/rm -rf "$app" ;;
    *) echo "Refusing unsafe TCC fixture cleanup path: $app" >&2 ;;
  esac
}
trap cleanup EXIT HUP INT TERM

/bin/mkdir -p "$container"
cleanup

/usr/bin/osacompile -o "$app" \
  -e 'tell application "Finder" to get name of startup disk' \
  -e 'display dialog "Nick TCC fixture completed." buttons {"OK"} default button "OK"'
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $identifier" "$app/Contents/Info.plist" 2>/dev/null \
  || /usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string $identifier" "$app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :NSAppleEventsUsageDescription Nick scorecard fixture requests one synthetic Finder Apple Event." "$app/Contents/Info.plist" 2>/dev/null \
  || /usr/libexec/PlistBuddy -c "Add :NSAppleEventsUsageDescription string Nick scorecard fixture requests one synthetic Finder Apple Event." "$app/Contents/Info.plist"
/usr/bin/codesign --force --sign - "$app"
"$lsregister" -f "$app"

echo "Opening a bundled test applet ($identifier)."
echo "Unbundled AppleScript applets may appear in macOS UI only as 'applet'; this fixture uses an explicit bundle ID."
/usr/bin/open "$app"
printf 'If an Apple Events prompt appears, click Allow. If only the fixture OK dialog appears, click OK. Then press Return here: '
IFS= read -r _
if ! /usr/bin/tccutil reset AppleEvents "$identifier"; then
  echo "Fixture setup failed: macOS did not register $identifier as a TCC client." >&2
  exit 1
fi
echo "Reset AppleEvents permission for $identifier; waiting for Nick to persist the TCC change."
sleep 3
