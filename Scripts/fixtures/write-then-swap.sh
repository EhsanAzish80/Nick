#!/bin/sh
set -eu
root="${HOME}/Documents/NickScorecard"
mkdir -p "$root"
trap 'rm -rf "$root"' EXIT
i=1
while [ "$i" -le 200 ]; do
  target="$root/document-$i.txt"
  printf 'original document %s\n' "$i" > "$target"
  i=$((i + 1))
done
/usr/bin/python3 - "$root" <<'PY'
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
for index in range(1, 201):
    target = root / f"document-{index}.txt"
    temporary = root / f".document-{index}.tmp"
    temporary.write_bytes(os.urandom(2048))
    os.replace(temporary, root / f"document-{index}.txt.locked")
    target.unlink(missing_ok=True)
(root / "README_RESTORE_FILES.txt").write_text(
    "NICK SCORECARD FIXTURE: harmless ransomware-detection test files.\n",
    encoding="utf-8",
)
PY
sleep 1
