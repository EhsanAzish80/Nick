#!/bin/zsh

set -euo pipefail

export COPYFILE_DISABLE=1

if (( $# != 1 )); then
  print -u2 "Usage: $0 /path/to/Nick.pkg"
  exit 64
fi

PACKAGE_PATH=$1
[[ -f "${PACKAGE_PATH}" ]] || {
  print -u2 "Installer package not found: ${PACKAGE_PATH}"
  exit 66
}
PACKAGE_PATH=${PACKAGE_PATH:A}

AUDIT_DIR=$(mktemp -d /private/tmp/NickPackageAudit.XXXXXX)
trap 'rm -rf "${AUDIT_DIR}"' EXIT

(
  cd "${AUDIT_DIR}"
  xar -xf "${PACKAGE_PATH}" Payload
)

PAYLOAD_PATH="${AUDIT_DIR}/Payload"
[[ -f "${PAYLOAD_PATH}" ]] || {
  print -u2 "Installer package has no payload: ${PACKAGE_PATH}"
  exit 65
}

APPLEDOUBLE_LIST="${AUDIT_DIR}/appledouble-paths.txt"
gzip -dc "${PAYLOAD_PATH}" \
  | cpio -it 2>/dev/null \
  | awk -F/ '$NF ~ /^\._/ { print }' \
  > "${APPLEDOUBLE_LIST}"

APPLEDOUBLE_COUNT=$(wc -l < "${APPLEDOUBLE_LIST}" | tr -d ' ')
print "Installer raw-payload AppleDouble entries: ${APPLEDOUBLE_COUNT}"

if (( APPLEDOUBLE_COUNT > 0 )); then
  print -u2 "Installer payload contains AppleDouble metadata; refusing release."
  sed -n '1,20p' "${APPLEDOUBLE_LIST}" >&2
  exit 1
fi
