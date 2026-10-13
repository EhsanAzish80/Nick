#!/bin/zsh
set -euo pipefail

export COPYFILE_DISABLE=1

SCRIPT_DIR=${0:A:h}
PROJECT_DIR=${SCRIPT_DIR:h}
# Xcode's signing products must live outside the workspace's File Provider
# volume. The provider can attach FinderInfo between a cleanup phase and the
# following CodeSign command, making an otherwise clean archive fail.
# Use /private/tmp explicitly. The per-user TMPDIR lives under a managed
# filesystem on current macOS builds and can synthesize AppleDouble sidecars
# while pkgbuild walks signed bundles.
EXPECTED_VERSION=${EXPECTED_VERSION:-4.6.3}
EXPECTED_BUILD=${EXPECTED_BUILD:-430}
[[ "${EXPECTED_BUILD}" == <-> ]] || {
  print -u2 "Release build must be a positive integer; received '${EXPECTED_BUILD}'."
  exit 1
}
BUILD_DIR=${BUILD_DIR:-"/private/tmp/NickBuild-${EXPECTED_BUILD}"}
ARCHIVE_PATH=${ARCHIVE_PATH:-"${BUILD_DIR}/Nick.xcarchive"}
DERIVED_DATA_PATH=${DERIVED_DATA_PATH:-"${BUILD_DIR}/DerivedData"}
EXPORT_PATH=${EXPORT_PATH:-"${BUILD_DIR}/Export"}
OUTPUT_PATH=${OUTPUT_PATH:-"${BUILD_DIR}/Nick-${EXPECTED_VERSION}-build-${EXPECTED_BUILD}.pkg"}
LOCAL_PACKAGE_PATH=${LOCAL_PACKAGE_PATH:-"${BUILD_DIR}/Nick-${EXPECTED_VERSION}-build-${EXPECTED_BUILD}.pkg"}
PAYLOAD_ROOT=${PAYLOAD_ROOT:-"${BUILD_DIR}/InstallerRoot"}
APP_SIGNING_IDENTITY=${APP_SIGNING_IDENTITY:-"Developer ID Application: ehsan azish (UXGW5V3BY6)"}
INSTALLER_SIGNING_IDENTITY=${INSTALLER_SIGNING_IDENTITY:-"Developer ID Installer: ehsan azish (UXGW5V3BY6)"}
NOTARY_PROFILE=${NOTARY_PROFILE:-NickNotary}
NOTARIZE=${NOTARIZE:-1}
SPARKLE_ACCOUNT=${SPARKLE_ACCOUNT:-nick-legacy}
SPARKLE_BIN=${SPARKLE_BIN:-"${DERIVED_DATA_PATH}/SourcePackages/artifacts/sparkle/Sparkle/bin"}

"${PROJECT_DIR}/Scripts/validate-extension-build.sh" "${EXPECTED_BUILD}"

mkdir -p "${BUILD_DIR}"

# A release archive must never reuse products whose resource forks or Finder
# metadata were materialized by an earlier Xcode/File Provider build. Reusing
# DerivedData made signing success depend on the previous local build state.
rm -rf "${ARCHIVE_PATH}" "${DERIVED_DATA_PATH}" "${EXPORT_PATH}" \
  "${PAYLOAD_ROOT}" "${BUILD_DIR}/ExpandedPackage"
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
  MARKETING_VERSION="${EXPECTED_VERSION}" \
  CURRENT_PROJECT_VERSION="${EXPECTED_BUILD}" \
  archive

xcodebuild -exportArchive \
  -archivePath "${ARCHIVE_PATH}" \
  -exportPath "${EXPORT_PATH}" \
  -exportOptionsPlist "${PROJECT_DIR}/Nick/Scripts/ExportOptions.plist"

EXPORTED_APP="${EXPORT_PATH}/Nick.app"
"${SCRIPT_DIR}/stage-package-root.sh" "${EXPORTED_APP}" "${PAYLOAD_ROOT}"

NICK_APP="${PAYLOAD_ROOT}/Applications/Nick.app"
UNINSTALLER="${NICK_APP}/Contents/Applications/Nick Uninstaller.app"
STANDALONE_UNINSTALLER="${PAYLOAD_ROOT}/Applications/Nick Uninstaller.app"
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

for extension in NickExtension NickNetFilter; do
  extension_plist="${NICK_APP}/Contents/Library/SystemExtensions/com.ehsanazish.nick.${extension}.systemextension/Contents/Info.plist"
  extension_build=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "${extension_plist}")
  [[ "${extension_build}" == "${EXPECTED_BUILD}" ]] || {
    print -u2 "Expected ${extension} build ${EXPECTED_BUILD}, found ${extension_build}."
    exit 1
  }
done

for plist in \
  "${UNINSTALLER}/Contents/Info.plist" \
  "${STANDALONE_UNINSTALLER}/Contents/Info.plist"; do
  component_build=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "${plist}")
  [[ "${component_build}" == "${EXPECTED_BUILD}" ]] || {
    print -u2 "Expected every bundled component at build ${EXPECTED_BUILD}; ${plist} contains ${component_build}."
    exit 1
  }
done

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
# Verify the exact bundle that will be handed to the package builder.
codesign --verify --deep --strict --verbose=2 "${NICK_APP}"

# Verify the exact signed application and standalone uninstaller that pkgbuild
# will consume. There is no post-signing copy step.
codesign --verify --deep --strict --verbose=2 \
  "${NICK_APP}"
codesign --verify --deep --strict --verbose=2 \
  "${STANDALONE_UNINSTALLER}"

"${SCRIPT_DIR}/build-clean-component-package.sh" \
  "${PAYLOAD_ROOT}" \
  com.ehsanazish.nick.pkg \
  "${VERSION}.${BUILD}" \
  "${INSTALLER_SIGNING_IDENTITY}" \
  "${LOCAL_PACKAGE_PATH}"

"${SCRIPT_DIR}/audit-package-payload.sh" "${LOCAL_PACKAGE_PATH}"

PACKAGE_SIGNATURE=$(LC_ALL=C pkgutil --check-signature "${LOCAL_PACKAGE_PATH}" 2>&1) || {
  print -r -- "${PACKAGE_SIGNATURE}"
  print -u2 "Installer signature check failed; refusing release."
  exit 1
}
print -r -- "${PACKAGE_SIGNATURE}"
if print -r -- "${PACKAGE_SIGNATURE}" | grep -Eq \
  'Status: (invalid signature|no signature)'; then
  print -u2 "Installer signature is not valid; refusing release."
  exit 1
fi
if ! print -r -- "${PACKAGE_SIGNATURE}" | grep -q \
  'Developer ID Installer: ehsan azish (UXGW5V3BY6)'; then
  print -u2 "Installer is not signed with the expected Developer ID Installer identity."
  exit 1
fi

EXPANDED_PACKAGE="${BUILD_DIR}/ExpandedPackage"
rm -rf "${EXPANDED_PACKAGE}"
pkgutil --expand-full "${LOCAL_PACKAGE_PATH}" "${EXPANDED_PACKAGE}"
codesign --verify --deep --strict --verbose=2 \
  "${EXPANDED_PACKAGE}/Payload/Applications/Nick.app"

# Only move the completed, audited flat package onto a shared or externally
# managed destination. Building there can cause copyfile metadata sidecars to
# be serialized into the package payload itself.
if [[ "${LOCAL_PACKAGE_PATH}" != "${OUTPUT_PATH}" ]]; then
  rm -f "${OUTPUT_PATH}"
  ditto --norsrc --noextattr --noqtn \
    "${LOCAL_PACKAGE_PATH}" "${OUTPUT_PATH}"
fi

LOCAL_PACKAGE_SHA=$(shasum -a 256 "${LOCAL_PACKAGE_PATH}" | awk '{print $1}')
OUTPUT_PACKAGE_SHA=$(shasum -a 256 "${OUTPUT_PATH}" | awk '{print $1}')
[[ "${LOCAL_PACKAGE_SHA}" == "${OUTPUT_PACKAGE_SHA}" ]] || {
  print -u2 "Release package changed while copying to its output destination."
  exit 1
}

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

if [[ "${VALIDATE_LIVE_APPCAST:-0}" == "1" ]]; then
  "${SCRIPT_DIR}/validate-live-appcast.sh" \
    "${LIVE_APPCAST_URL:-https://3nsofts.com/nick/appcast.xml}" \
    "${EXPECTED_BUILD}"
fi
