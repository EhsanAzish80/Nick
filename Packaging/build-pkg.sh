#!/bin/zsh
set -euo pipefail

SCRIPT_DIR=${0:A:h}
PROJECT_DIR=${SCRIPT_DIR:h}
BUILD_DIR=${BUILD_DIR:-"${PROJECT_DIR}/build/package"}
CONFIGURATION=${CONFIGURATION:-Release}
ARCHIVE_PATH=${ARCHIVE_PATH:-"${BUILD_DIR}/Nick.xcarchive"}
OUTPUT_PATH=${OUTPUT_PATH:-"${BUILD_DIR}/Nick.pkg"}
INSTALLER_SIGNING_IDENTITY=${INSTALLER_SIGNING_IDENTITY:-}
EXTENSION_BUILD=$(xcodebuild -project "${PROJECT_DIR}/Nick.xcodeproj" -target NickExtension -configuration "${CONFIGURATION}" -showBuildSettings \
  | /usr/bin/awk '/CURRENT_PROJECT_VERSION/ { print $3; exit }')

"${PROJECT_DIR}/Scripts/validate-extension-build.sh" "${EXTENSION_BUILD}"

rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"

xcodebuild \
  -project "${PROJECT_DIR}/Nick.xcodeproj" \
  -scheme Nick \
  -configuration "${CONFIGURATION}" \
  -archivePath "${ARCHIVE_PATH}" \
  archive

NICK_APP="${ARCHIVE_PATH}/Products/Applications/Nick.app"
EMBEDDED_UNINSTALLER="${NICK_APP}/Contents/Applications/Nick Uninstaller.app"

if [[ ! -d "${NICK_APP}" ]]; then
  print -u2 "Nick.app was not found in the archive."
  exit 1
fi

if [[ ! -d "${EMBEDDED_UNINSTALLER}" ]]; then
  print -u2 "Nick Uninstaller.app was not embedded in Nick.app."
  exit 1
fi

for extension in NickExtension NickNetFilter; do
  extension_plist="${NICK_APP}/Contents/Library/SystemExtensions/com.ehsanazish.nick.${extension}.systemextension/Contents/Info.plist"
  extension_build=$(/usr/libexec/PlistBuddy -c "Print :CFBundleVersion" "${extension_plist}")
  [[ "${extension_build}" == "${EXTENSION_BUILD}" ]] || {
    print -u2 "Expected ${extension} build ${EXTENSION_BUILD}, found ${extension_build}."
    exit 1
  }
done

PKG_ARGS=(
  --component "${NICK_APP}" /Applications
  --component "${EMBEDDED_UNINSTALLER}" /Applications
)

if [[ -n "${INSTALLER_SIGNING_IDENTITY}" ]]; then
  PKG_ARGS+=(--sign "${INSTALLER_SIGNING_IDENTITY}")
else
  print -u2 "Warning: INSTALLER_SIGNING_IDENTITY is empty; producing an unsigned development package."
fi

productbuild "${PKG_ARGS[@]}" "${OUTPUT_PATH}"

print "Created ${OUTPUT_PATH}"
print "Before distribution, sign with Developer ID Installer, notarize, staple, and test on a clean Mac."
