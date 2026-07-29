#!/bin/zsh
set -euo pipefail

SCRIPT_DIR=${0:A:h}
PROJECT_DIR=${SCRIPT_DIR:h}
BUILD_DIR=${BUILD_DIR:-"${PROJECT_DIR}/build/release"}
ARCHIVE_PATH=${ARCHIVE_PATH:-"${BUILD_DIR}/Nick.xcarchive"}
EXPECTED_VERSION=${EXPECTED_VERSION:-4.0.1}
EXPECTED_BUILD=${EXPECTED_BUILD:-405}
OUTPUT_PATH=${OUTPUT_PATH:-"${BUILD_DIR}/Nick-${EXPECTED_VERSION}-build-${EXPECTED_BUILD}.pkg"}
STAGING_DIR=${STAGING_DIR:-"${TMPDIR%/}/NickReleaseStaging"}
APP_SIGNING_IDENTITY=${APP_SIGNING_IDENTITY:-"Developer ID Application: ehsan azish (UXGW5V3BY6)"}
INSTALLER_SIGNING_IDENTITY=${INSTALLER_SIGNING_IDENTITY:-"Developer ID Installer: ehsan azish (UXGW5V3BY6)"}
NOTARY_PROFILE=${NOTARY_PROFILE:-NickNotary}
SPARKLE_ACCOUNT=${SPARKLE_ACCOUNT:-nick-legacy}
SPARKLE_BIN=${SPARKLE_BIN:-"${HOME}/Library/Developer/Xcode/DerivedData/Nick-gzbanxnqyyulqpeimhnitfvuobud/SourcePackages/artifacts/sparkle/Sparkle/bin"}

mkdir -p "${BUILD_DIR}"

xcodebuild \
  -project "${PROJECT_DIR}/Nick.xcodeproj" \
  -scheme Nick \
  -configuration Release \
  -archivePath "${ARCHIVE_PATH}" \
  archive

ARCHIVED_APP="${ARCHIVE_PATH}/Products/Applications/Nick.app"
rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}"
# Sign and package from a local temporary volume. The project can live in an
# iCloud/File Provider directory that rematerializes FinderInfo attributes
# after `xattr -c`, which makes otherwise valid nested Sparkle code fail strict
# signature verification.
ditto --noextattr --noqtn "${ARCHIVED_APP}" "${STAGING_DIR}/Nick.app"
NICK_APP="${STAGING_DIR}/Nick.app"
UNINSTALLER="${NICK_APP}/Contents/Applications/Nick Uninstaller.app"
SPARKLE_FRAMEWORK="${NICK_APP}/Contents/Frameworks/Sparkle.framework"

[[ -d "${NICK_APP}" ]] || { print -u2 "Nick.app is missing from the archive."; exit 1; }
[[ -d "${UNINSTALLER}" ]] || { print -u2 "Nick Uninstaller.app is missing."; exit 1; }
[[ -x "${SPARKLE_BIN}/sign_update" ]] || { print -u2 "Sparkle signing tools were not found."; exit 1; }

VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "${NICK_APP}/Contents/Info.plist")
BUILD=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "${NICK_APP}/Contents/Info.plist")
[[ "${VERSION}" == "${EXPECTED_VERSION}" && "${BUILD}" == "${EXPECTED_BUILD}" ]] || {
  print -u2 "Expected Nick ${EXPECTED_VERSION} (${EXPECTED_BUILD}), found ${VERSION} (${BUILD})."
  exit 1
}

# Remove Finder metadata before signing and packaging. Otherwise productbuild
# can emit AppleDouble `._*` entries and noisy "write: Permission denied"
# diagnostics when copying a previously inspected archive.
xattr -cr "${NICK_APP}"

# Sparkle ships pre-signed helpers. Notarization requires every nested helper
# to carry our Developer ID identity and a secure timestamp.
codesign --force --deep --options runtime --timestamp \
  --sign "${APP_SIGNING_IDENTITY}" "${SPARKLE_FRAMEWORK}"
# Re-signing a nested framework can cause filesystem-provider metadata to be
# materialized again on this volume. Strip it once more immediately before the
# containing app's sealed-resource signature is created. `xattr -r` does not
# traverse Sparkle's `Versions/Current` symlink, so clean the real version too.
xattr -cr "${NICK_APP}"
xattr -cr "${SPARKLE_FRAMEWORK}/Versions/B"
codesign --force --options runtime --timestamp \
  --preserve-metadata=identifier,entitlements,requirements,flags,runtime \
  --sign "${APP_SIGNING_IDENTITY}" "${NICK_APP}"
codesign --verify --deep --strict --verbose=2 "${NICK_APP}"

productbuild \
  --component "${NICK_APP}" /Applications \
  --component "${UNINSTALLER}" /Applications \
  --sign "${INSTALLER_SIGNING_IDENTITY}" \
  "${OUTPUT_PATH}"

xcrun notarytool submit "${OUTPUT_PATH}" \
  --keychain-profile "${NOTARY_PROFILE}" \
  --wait
xcrun stapler staple "${OUTPUT_PATH}"
xcrun stapler validate "${OUTPUT_PATH}"
spctl -a -vv -t install "${OUTPUT_PATH}"

print
print "Sparkle enclosure attributes:"
"${SPARKLE_BIN}/sign_update" --account "${SPARKLE_ACCOUNT}" "${OUTPUT_PATH}"
print
shasum -a 256 "${OUTPUT_PATH}"
