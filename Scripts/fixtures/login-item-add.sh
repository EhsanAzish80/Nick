#!/bin/sh
set -eu

root=${NICK_FIXTURE_ROOT:-/tmp/NickScorecard-login-item}
app="$root/Nick Login Item Fixture.app"
identifier="com.3nsofts.nick.scorecard.loginitem.$(date +%s)"

cleanup() {
  /usr/bin/osascript - "$identifier" <<'APPLESCRIPT' >/dev/null 2>&1 || true
on run argv
  tell application "System Events"
    if exists login item (item 1 of argv) then delete login item (item 1 of argv)
  end tell
end run
APPLESCRIPT
  /bin/rm -rf "$root"
}
trap cleanup EXIT INT TERM

/bin/mkdir -p "$root"
/usr/bin/osacompile -o "$app" -e 'on run' -e 'display dialog "Nick scorecard login item fixture" buttons {"OK"}' -e 'end run'
/usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string $identifier" "$app/Contents/Info.plist" \
  || /usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $identifier" "$app/Contents/Info.plist"
/usr/bin/codesign --force --sign - "$app" >/dev/null

/usr/bin/osascript - "$identifier" "$app" <<'APPLESCRIPT'
on run argv
  tell application "System Events"
    make new login item at end with properties {name:(item 1 of argv), path:(item 2 of argv), hidden:true}
  end tell
end run
APPLESCRIPT

/bin/sleep 8
