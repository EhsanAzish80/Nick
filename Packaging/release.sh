#!/bin/zsh
set -euo pipefail

SCRIPT_DIR=${0:A:h}
PROJECT_DIR=${SCRIPT_DIR:h}
# Xcode's signing products must live outside the workspace's File Provider
# volume. The provider can attach FinderInfo between a cleanup phase and the
# following CodeSign command, making an otherwise clean archive fail.
# Use /private/tmp explicitly. The per-user TMPDIR lives under a managed
# filesystem on current macOS builds and can synthesize AppleDouble sidecars
# while pkgbuild walks signed bundles.
BUILD_DIR=${BUILD_DIR:-"/private/tmp/NickReleaseBuild"}
ARCHIVE_PATH=${ARCHIVE_PATH:-"${BUILD_DIR}/Nick.xcarchive"}
DERIVED_DATA_PATH=${DERIVED_DATA_PATH:-"${BUILD_DIR}/DerivedData"}
EXPECTED_VERSION=${EXPECTED_VERSION:-4.3}
EXPECTED_BUILD=${EXPECTED_BUILD:-421}
OUTPUT_PATH=${OUTPUT_PATH:-"${BUILD_DIR}/Nick-${EXPECTED_VERSION}-build-${EXPECTED_BUILD}.pkg"}
LOCAL_PACKAGE_PATH=${LOCAL_PACKAGE_PATH:-"${BUILD_DIR}/Nick-${EXPECTED_VERSION}-build-${EXPECTED_BUILD}.pkg"}
STAGING_DIR=${STAGING_DIR:-"/private/tmp/NickReleaseStaging"}
APP_SIGNING_IDENTITY=${APP_SIGNING_IDENTITY:-"Developer ID Application: ehsan azish (UXGW5V3BY6)"}
INSTALLER_SIGNING_IDENTITY=${INSTALLER_SIGNING_IDENTITY:-"Developer ID Installer: ehsan azish (UXGW5V3BY6)"}
NOTARY_PROFILE=${NOTARY_PROFILE:-NickNotary}
NOTARIZE=${NOTARIZE:-1}
SPARKLE_ACCOUNT=${SPARKLE_ACCOUNT:-nick-legacy}
SPARKLE_BIN=${SPARKLE_BIN:-"${DERIVED_DATA_PATH}/SourcePackages/artifacts/sparkle/Sparkle/bin"}

mkdir -p "${BUILD_DIR}"

# A release archive must never reuse products whose resource forks or Finder
# metadata were materialized by an earlier Xcode/File Provider build. Reusing
# DerivedData made signing success depend on the previous local build state.
rm -rf "${ARCHIVE_PATH}" "${DERIVED_DATA_PATH}"
xattr -cr \
  "${PROJECT_DIR}/Nick" \
  "${PROJECT_DIR}/NickExtension" \
  "${PROJECT_DIR}/NickNetFilter" \
  "${PROJECT_DIR}/NickUninstaller" \
  "${PROJECT_DIR}/Rules" 2>/dev/null || true

xcodebuild \
  -project "${PROJECT_DIR}/Nick.xcodeproj" \
  -scheme Nick \
  -configuration Release \
  -derivedDataPath "${DERIVED_DATA_PATH}" \
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
# Current macOS can attach provenance metadata to signed bundles. Do not strip
# the signed app after this point: doing so can invalidate nested signatures.
# Verify the exact bundle that will be handed to productbuild.
codesign --verify --deep --strict --verbose=2 "${NICK_APP}"

# Build from an explicit payload root instead of asking productbuild to copy
# signed component bundles. On some macOS/File Provider combinations,
# productbuild's component copier serializes extended attributes as AppleDouble
# `._*` files even when the source bundle itself is clean.
PAYLOAD_ROOT="${BUILD_DIR}/InstallerRoot"
rm -rf "${PAYLOAD_ROOT}"
mkdir -p "${PAYLOAD_ROOT}/Applications"
COPYFILE_DISABLE=1 ditto --noextattr --noqtn \
  "${NICK_APP}" "${PAYLOAD_ROOT}/Applications/Nick.app"
COPYFILE_DISABLE=1 ditto --noextattr --noqtn \
  "${UNINSTALLER}" "${PAYLOAD_ROOT}/Applications/Nick Uninstaller.app"

# Copying must not change the signed application that users will install.
codesign --verify --deep --strict --verbose=2 \
  "${PAYLOAD_ROOT}/Applications/Nick.app"

COPYFILE_DISABLE=1 pkgbuild \
  --root "${PAYLOAD_ROOT}" \
  --install-location / \
  --identifier com.ehsanazish.nick.pkg \
  --version "${VERSION}.${BUILD}" \
  --ownership recommended \
  --sign "${INSTALLER_SIGNING_IDENTITY}" \
  "${LOCAL_PACKAGE_PATH}"

EXPANDED_PACKAGE="${BUILD_DIR}/ExpandedPackage"
rm -rf "${EXPANDED_PACKAGE}"
pkgutil --expand-full "${LOCAL_PACKAGE_PATH}" "${EXPANDED_PACKAGE}"
APPLEDOUBLE_COUNT=$(find "${EXPANDED_PACKAGE}" -name '._*' -print | wc -l | tr -d ' ')
print "Installer AppleDouble metadata entries: ${APPLEDOUBLE_COUNT}"
if (( APPLEDOUBLE_COUNT > 0 )); then
  print -u2 "Installer payload contains AppleDouble metadata; refusing to notarize it."
  exit 1
fi

# Only move the completed, audited flat package onto a shared or externally
# managed destination. Building there can cause copyfile metadata sidecars to
# be serialized into the package payload itself.
if [[ "${LOCAL_PACKAGE_PATH}" != "${OUTPUT_PATH}" ]]; then
  rm -f "${OUTPUT_PATH}"
  COPYFILE_DISABLE=1 ditto --noextattr --noqtn \
    "${LOCAL_PACKAGE_PATH}" "${OUTPUT_PATH}"
fi

if [[ "${NOTARIZE}" == "1" ]]; then
  xcrun notarytool submit "${OUTPUT_PATH}" \
    --keychain-profile "${NOTARY_PROFILE}" \
    --wait
  xcrun stapler staple "${OUTPUT_PATH}"
  xcrun stapler validate "${OUTPUT_PATH}"
  spctl -a -vv -t install "${OUTPUT_PATH}"
else
  print "Skipping Apple notarization (NOTARIZE=${NOTARIZE})."
  pkgutil --check-signature "${OUTPUT_PATH}"
fi

print
print "Sparkle enclosure attributes:"
"${SPARKLE_BIN}/sign_update" --account "${SPARKLE_ACCOUNT}" "${OUTPUT_PATH}"
print
shasum -a 256 "${OUTPUT_PATH}"
