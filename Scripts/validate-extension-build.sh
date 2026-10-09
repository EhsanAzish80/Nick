#!/bin/zsh
set -euo pipefail

EXPECTED_BUILD=${1:-}
[[ "${EXPECTED_BUILD}" == <-> ]] || {
  print -u2 "Endpoint extension build must be a positive integer; received '${EXPECTED_BUILD}'."
  exit 1
}

# A same-number replacement can leave macOS running the previous system
# extension. Refuse to produce an installable package when this Mac already
# has that build (or a newer one) active.
if ! EXTENSION_LIST=$(/usr/bin/systemextensionsctl list 2>&1); then
  print -u2 "Could not read active system extensions; refusing to build an installable package."
  print -u2 "${EXTENSION_LIST}"
  exit 1
fi

ACTIVE_BUILDS=$(print -r -- "${EXTENSION_LIST}" \
  | /usr/bin/awk '/com\.ehsanazish\.nick\.(NickExtension|NickNetFilter)/ && /\[activated enabled\]/ { print $0 }' \
  | /usr/bin/sed -E 's/.*\([^/]+\/([0-9]+)\).*/\1/' \
  | /usr/bin/grep -E '^[0-9]+$' || true)

for active in ${(f)ACTIVE_BUILDS}; do
  if (( EXPECTED_BUILD <= active )); then
    print -u2 "Refusing installable build ${EXPECTED_BUILD}: active Nick system extension build is ${active}."
    print -u2 "Choose a higher CURRENT_PROJECT_VERSION so macOS cannot retain stale extension code."
    exit 1
  fi
done

print "Endpoint extension build ${EXPECTED_BUILD} is newer than every active Nick extension build."
