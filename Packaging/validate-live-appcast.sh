#!/bin/zsh
set -euo pipefail

APPCAST_URL=${1:?appcast URL required}
EXPECTED_BUILD=${2:?expected build required}
WORK_DIR=$(mktemp -d /private/tmp/NickAppcastValidation.XXXXXX)
trap 'rm -rf "${WORK_DIR}"' EXIT
APPCAST_PATH="${WORK_DIR}/appcast.xml"

curl --fail --silent --show-error --location "${APPCAST_URL}" --output "${APPCAST_PATH}"
xmllint --noout "${APPCAST_PATH}"

xpath() { xmllint --xpath "$1" "${APPCAST_PATH}"; }
CURRENT_BUILD=$(xpath 'string((//*[local-name()="item"])[1]/*[local-name()="version"])')
PREVIOUS_BUILD=$(xpath 'string((//*[local-name()="item"])[2]/*[local-name()="version"])')
SIGNATURE=$(xpath 'string((//*[local-name()="item"])[1]/*[local-name()="enclosure"]/@*[local-name()="edSignature"])')
DECLARED_LENGTH=$(xpath 'string((//*[local-name()="item"])[1]/*[local-name()="enclosure"]/@length)')
PACKAGE_URL=$(xpath 'string((//*[local-name()="item"])[1]/*[local-name()="enclosure"]/@url)')

[[ "${CURRENT_BUILD}" == "${EXPECTED_BUILD}" ]] || { print -u2 "Unexpected live build: ${CURRENT_BUILD}"; exit 1; }
(( CURRENT_BUILD > PREVIOUS_BUILD )) || { print -u2 "Build ${CURRENT_BUILD} is not newer than ${PREVIOUS_BUILD}."; exit 1; }
[[ -n "${SIGNATURE}" ]] || { print -u2 "Missing Sparkle signature."; exit 1; }
ACTUAL_LENGTH=$(curl --fail --silent --show-error --location "${PACKAGE_URL}" | wc -c | tr -d ' ')
[[ "${ACTUAL_LENGTH}" == "${DECLARED_LENGTH}" ]] || { print -u2 "Package length mismatch: ${ACTUAL_LENGTH} != ${DECLARED_LENGTH}"; exit 1; }
print "Live appcast valid: build ${CURRENT_BUILD}, previous ${PREVIOUS_BUILD}, package length ${ACTUAL_LENGTH}."
