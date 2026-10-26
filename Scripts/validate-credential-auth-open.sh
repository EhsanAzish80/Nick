#!/bin/zsh
set -euo pipefail

# Installed-build proof for the AUTH_OPEN credential path. This fixture uses a
# synthetic file and an ad-hoc helper; it never reads a real credential.
health='/Library/Application Support/com.ehsanazish.nick/extension_health.json'
incidents='/Library/Application Support/com.ehsanazish.nick/state/incidents.json'
work="$(mktemp -d /private/tmp/nick-auth-open.XXXXXX)"
trap 'rm -rf "$work"' EXIT

read_health_count() {
  sudo /usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], 0))' "$health" "$1"
}

count_fixture_incidents() {
  sudo /usr/bin/python3 -c '
import json, sys
value = json.load(open(sys.argv[1]))
needle = sys.argv[2]
def walk(node):
    if isinstance(node, dict):
        encoded = json.dumps(node, sort_keys=True)
        here = int("credential_store_access" in encoded and needle in encoded)
        return here + sum(walk(v) for v in node.values())
    if isinstance(node, list):
        return sum(walk(v) for v in node)
    return 0
print(walk(value))
' "$incidents" "$work/Login Data"
}

if [[ ! -r "$health" ]]; then
  echo 'FAIL: installed endpoint extension health is unavailable'
  exit 1
fi

before_evaluated="$(read_health_count credentialOpenEvaluationCount)"
before_findings="$(read_health_count credentialOpenFindingCount)"
before_incidents="$(count_fixture_incidents 2>/dev/null || echo 0)"

printf 'synthetic-only\n' > "$work/Login Data"
printf '%s\n' '#include <fcntl.h>' '#include <unistd.h>' \
  'int main(int argc, char **argv) { if (argc != 2) return 2; int fd = open(argv[1], O_RDONLY); if (fd < 0) return 3; char byte; (void)read(fd, &byte, 1); close(fd); return 0; }' \
  > "$work/open-fixture.c"
/usr/bin/clang "$work/open-fixture.c" -o "$work/open-fixture"
/usr/bin/codesign --remove-signature "$work/open-fixture" 2>/dev/null || true
"$work/open-fixture" "$work/Login Data"

for _ in {1..30}; do
  sleep 0.2
  after_evaluated="$(read_health_count credentialOpenEvaluationCount)"
  after_findings="$(read_health_count credentialOpenFindingCount)"
  after_incidents="$(count_fixture_incidents 2>/dev/null || echo 0)"
  if (( after_evaluated > before_evaluated && after_findings > before_findings && after_incidents > before_incidents )); then
    echo "PASS: AUTH_OPEN evaluated and persisted the synthetic credential-store finding"
    exit 0
  fi
done

echo "FAIL: counters before=${before_evaluated}/${before_findings}, after=${after_evaluated:-?}/${after_findings:-?}; fixture incidents before=${before_incidents}, after=${after_incidents:-?}"
exit 1
