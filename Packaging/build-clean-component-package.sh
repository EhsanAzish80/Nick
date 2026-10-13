#!/bin/zsh

set -euo pipefail

export COPYFILE_DISABLE=1

if (( $# != 5 )); then
  print -u2 "Usage: $0 ROOT IDENTIFIER VERSION INSTALLER_IDENTITY OUTPUT.pkg"
  print -u2 "Pass an empty installer identity to produce an unsigned test package."
  exit 64
fi

PAYLOAD_ROOT=${1:A}
PACKAGE_IDENTIFIER=$2
PACKAGE_VERSION=$3
INSTALLER_IDENTITY=$4
OUTPUT_PATH=${5:A}

[[ -d "${PAYLOAD_ROOT}" ]] || {
  print -u2 "Package root not found: ${PAYLOAD_ROOT}"
  exit 66
}

WORK_DIR=$(mktemp -d /private/tmp/NickCleanPackage.XXXXXX)
trap 'rm -rf "${WORK_DIR}"' EXIT

# Let pkgbuild produce canonical PackageInfo metadata, but do not retain the
# payload it creates: current macOS can serialize protected provenance xattrs
# as AppleDouble even after xattr -cr and with COPYFILE_DISABLE enabled.
pkgbuild \
  --root "${PAYLOAD_ROOT}" \
  --install-location / \
  --identifier "${PACKAGE_IDENTIFIER}" \
  --version "${PACKAGE_VERSION}" \
  --ownership recommended \
  "${WORK_DIR}/metadata.pkg" >/dev/null

(
  cd "${WORK_DIR}"
  xar -xf metadata.pkg PackageInfo
)

mkbom "${PAYLOAD_ROOT}" "${WORK_DIR}/Bom"
(
  cd "${PAYLOAD_ROOT}"
  bsdtar --no-xattrs --format cpio -cf - . \
    | gzip -9 > "${WORK_DIR}/Payload"
)
(
  cd "${WORK_DIR}"
  xar -cf unsigned-clean.pkg Bom PackageInfo Payload
)

mkdir -p "${OUTPUT_PATH:h}"
if [[ -n "${INSTALLER_IDENTITY}" ]]; then
  productsign \
    --sign "${INSTALLER_IDENTITY}" \
    "${WORK_DIR}/unsigned-clean.pkg" \
    "${OUTPUT_PATH}"
else
  ditto --norsrc --noextattr --noqtn \
    "${WORK_DIR}/unsigned-clean.pkg" "${OUTPUT_PATH}"
fi
