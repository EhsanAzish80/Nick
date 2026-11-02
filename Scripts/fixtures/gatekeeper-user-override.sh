#!/bin/sh
set -eu

root="${NICK_FIXTURE_ROOT:?NICK_FIXTURE_ROOT is required}"
app="$root/Nick Gatekeeper Fixture.app"
identifier="com.3nsofts.nick.scorecard.gatekeeper"
lsregister="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

# Build an inert local applet and deliberately attach a synthetic quarantine
# attribute. The fixture contains no downloaded or executable payload beyond
# the applet's immediate `quit` command.
/usr/bin/osacompile -o "$app" -e 'on run' -e 'quit' -e 'end run'
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $identifier" "$app/Contents/Info.plist" 2>/dev/null \
  || /usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string $identifier" "$app/Contents/Info.plist"
/usr/bin/codesign --force --sign - "$app"
"$lsregister" -f "$app"

# A quarantine record contains a hexadecimal Unix timestamp. A zero timestamp
# does not model a real downloaded item and can bypass the normal Open Anyway
# workflow on some macOS releases.
timestamp_hex="$(/usr/bin/printf '%x' "$(/bin/date +%s)")"
/usr/bin/xattr -w com.apple.quarantine "0081;$timestamp_hex;NickScorecard;" "$app"

if /usr/sbin/spctl --assess --type execute "$app" >/dev/null 2>&1; then
  echo "Fixture setup failed: Gatekeeper accepted the ad-hoc scratch app before override." >&2
  exit 1
fi

echo "Opening the inert quarantined fixture ($identifier). Gatekeeper should refuse it."
/usr/bin/open "$app" || true
echo "In the Gatekeeper dialog choose Done. Do NOT choose Move to Trash."
printf 'After choosing Done, press Return here: '
IFS= read -r _

# Open the Security pane only after Gatekeeper has registered the refusal.
/usr/bin/open 'x-apple.systempreferences:com.apple.preference.security?General' || true
echo "In Privacy & Security, choose Open Anyway for Nick Gatekeeper Fixture, then confirm Open."
printf 'After the inert app opens and immediately closes, press Return here: '
IFS= read -r _
sleep 3
