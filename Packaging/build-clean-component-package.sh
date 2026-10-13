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
SCRIPT_DIR=${0:A:h}

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
  xar -xf metadata.pkg PackageInfo Payload
)

# Preserve pkgbuild's Installer-compatible portable-ASCII cpio records while
# removing only AppleDouble records. Re-creating the archive with a generic
# tar/cpio writer can produce a stream pkgutil and Installer reject.
gzip -dc "${WORK_DIR}/Payload" > "${WORK_DIR}/Payload.raw"
"${SCRIPT_DIR}/filter-appledouble-cpio.pl" \
  "${WORK_DIR}/Payload.raw" "${WORK_DIR}/Payload.clean.raw"
gzip -9 < "${WORK_DIR}/Payload.clean.raw" > "${WORK_DIR}/Payload"

# pkgbuild counted its synthesized AppleDouble records in PackageInfo. Keep the
# declared payload count consistent with the filtered archive or Installer will
# reject an otherwise valid odc stream as a malformed cpio payload.
PAYLOAD_FILE_COUNT=$(cpio -it < "${WORK_DIR}/Payload.clean.raw" 2>/dev/null \
  | wc -l | tr -d ' ')
PAYLOAD_INSTALL_KB=$(du -sk "${PAYLOAD_ROOT}" | awk '{print $1}')
perl -0pi -e \
  's{<payload numberOfFiles="[0-9]+" installKBytes="[0-9]+"/>}{<payload numberOfFiles="'"${PAYLOAD_FILE_COUNT}"'" installKBytes="'"${PAYLOAD_INSTALL_KB}"'"/>}' \
  "${WORK_DIR}/PackageInfo"

mkbom "${PAYLOAD_ROOT}" "${WORK_DIR}/Bom"
(
  cd "${WORK_DIR}"
  # Installer expects the already-gzipped Payload member to remain uncompressed
  # in the outer xar container, matching pkgbuild's package layout.
  xar -cf unsigned-clean.pkg --no-compress '^Payload$' \
    Bom PackageInfo Payload
)

# Force Installer to parse the completed unsigned package before productsign.
# On current macOS, signing a package whose payload has not yet been expanded
# can initially verify but become invalid after its first full expansion.
# Preflighting the exact unsigned bytes makes that parse happen before the
# signature is created, so later release audits cannot mutate signature state.
pkgutil --expand-full \
  "${WORK_DIR}/unsigned-clean.pkg" \
  "${WORK_DIR}/ExpandedUnsigned"

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
