#!/bin/zsh
set -euo pipefail

VENDORED=$(tr -d '[:space:]' < "${0:A:h}/../Nick/Core/YARAEngine/Vendor/YARA_VERSION.txt")
LATEST=$(curl --fail --silent --show-error https://api.github.com/repos/VirusTotal/yara/releases/latest \
  | /usr/bin/plutil -extract tag_name raw -o - -)
print "Vendored libyara: ${VENDORED}"
print "Latest libyara: ${LATEST#v}"
[[ "${VENDORED}" == "${LATEST#v}" ]] || {
  print -u2 "A newer libyara release is available."
  exit 1
}
