#!/bin/zsh

set -euo pipefail

export COPYFILE_DISABLE=1

if (( $# != 2 )); then
  print -u2 "Usage: $0 /path/to/Nick.app /path/to/InstallerRoot"
  exit 64
fi

SOURCE_APP=${1:A}
PAYLOAD_ROOT=${2:A}

[[ -d "${SOURCE_APP}" ]] || {
  print -u2 "Source application not found: ${SOURCE_APP}"
  exit 66
}

SOURCE_UNINSTALLER="${SOURCE_APP}/Contents/Applications/Nick Uninstaller.app"
[[ -d "${SOURCE_UNINSTALLER}" ]] || {
  print -u2 "Nick Uninstaller.app is missing from the source application."
  exit 66
}

rm -rf "${PAYLOAD_ROOT}"
mkdir -p "${PAYLOAD_ROOT}/Applications"

# Strip resource forks, extended attributes, and quarantine metadata while
# copying into the exact tree that pkgbuild will consume. Signing happens only
# after this script returns, so the sealed bundle cannot be dirtied by another
# package-root copy.
ditto --norsrc --noextattr --noqtn \
  "${SOURCE_APP}" "${PAYLOAD_ROOT}/Applications/Nick.app"
ditto --norsrc --noextattr --noqtn \
  "${SOURCE_UNINSTALLER}" "${PAYLOAD_ROOT}/Applications/Nick Uninstaller.app"
xattr -cr "${PAYLOAD_ROOT}"
