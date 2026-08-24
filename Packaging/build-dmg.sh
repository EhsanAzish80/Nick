#!/bin/zsh
set -euo pipefail

SCRIPT_DIR=${0:A:h}
PROJECT_DIR=${SCRIPT_DIR:h}
PKG_PATH=${PKG_PATH:-"/Users/Shared/Nick-4.5-build-426.pkg"}
OUTPUT_PATH=${OUTPUT_PATH:-"/Users/Shared/Nick-4.5-build-426.dmg"}
WORK_DIR=${WORK_DIR:-"${TMPDIR%/}/NickDMG426"}
VOLUME_NAME="Install Nick"
APP_SIGNING_IDENTITY=${APP_SIGNING_IDENTITY:-"Developer ID Application: ehsan azish (UXGW5V3BY6)"}
NOTARY_PROFILE=${NOTARY_PROFILE:-NickNotary}
NOTARIZE=${NOTARIZE:-1}
ICON_PATH="${PROJECT_DIR}/Nick/Resources/Assets.xcassets/AppIcon.appiconset/icon_1024x1024.png"

[[ -f "${PKG_PATH}" ]] || { print -u2 "Installer package not found: ${PKG_PATH}"; exit 1; }
[[ -f "${ICON_PATH}" ]] || { print -u2 "Nick icon not found: ${ICON_PATH}"; exit 1; }

rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}/root/.background"
cp "${PKG_PATH}" "${WORK_DIR}/root/Install Nick.pkg"

cat > "${WORK_DIR}/root/Read Me.txt" <<'EOF'
Install Nick

1. Double-click “Install Nick.pkg”.
2. Follow the installer.
3. Open Nick from Applications.
4. Nick will explain and verify each required macOS approval.

The installer includes Nick Uninstaller for complete removal.
EOF

"${SCRIPT_DIR}/make-dmg-background.swift" \
  "${ICON_PATH}" \
  "${WORK_DIR}/root/.background/background.png"

RW_DMG="${WORK_DIR}/Nick-readwrite.dmg"
rm -f "${RW_DMG}" "${OUTPUT_PATH}"
hdiutil create \
  -volname "${VOLUME_NAME}" \
  -srcfolder "${WORK_DIR}/root" \
  -fs HFS+ \
  -format UDRW \
  -ov \
  "${RW_DMG}"

ATTACH_OUTPUT=$(hdiutil attach "${RW_DMG}" -readwrite -noverify -noautoopen)
DEVICE=$(print -r -- "${ATTACH_OUTPUT}" | awk '/Apple_HFS/ { print $1; exit }')
[[ -n "${DEVICE}" ]] || { print -u2 "Could not attach the DMG."; exit 1; }
trap 'hdiutil detach "${DEVICE}" -force >/dev/null 2>&1 || true' EXIT

osascript <<EOF
tell application "Finder"
    tell disk "${VOLUME_NAME}"
        open
        set current view of container window to icon view
        set toolbar visible of container window to false
        set statusbar visible of container window to false
        set bounds of container window to {120, 120, 840, 560}
        set theViewOptions to the icon view options of container window
        set arrangement of theViewOptions to not arranged
        set icon size of theViewOptions to 96
        set text size of theViewOptions to 13
        set background picture of theViewOptions to file ".background:background.png"
        set position of item "Install Nick.pkg" of container window to {360, 270}
        set position of item "Read Me.txt" of container window to {620, 370}
        update without registering applications
        delay 2
        close
    end tell
end tell
EOF

sync
hdiutil detach "${DEVICE}"
trap - EXIT
hdiutil convert "${RW_DMG}" -format UDZO -imagekey zlib-level=9 -o "${OUTPUT_PATH}"

codesign --force --timestamp --sign "${APP_SIGNING_IDENTITY}" "${OUTPUT_PATH}"
if [[ "${NOTARIZE}" == "1" ]]; then
  xcrun notarytool submit "${OUTPUT_PATH}" --keychain-profile "${NOTARY_PROFILE}" --wait
  xcrun stapler staple "${OUTPUT_PATH}"
  xcrun stapler validate "${OUTPUT_PATH}"
  spctl -a -vv -t open --context context:primary-signature "${OUTPUT_PATH}"
else
  print "Skipping Apple notarization (NOTARIZE=${NOTARIZE})."
  codesign --verify --verbose=2 "${OUTPUT_PATH}"
fi
shasum -a 256 "${OUTPUT_PATH}"
