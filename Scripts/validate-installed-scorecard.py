#!/usr/bin/env python3
"""Guide and record the installed 24-technique replay without inventing results.

Run this script with sudo after installing the candidate. It snapshots Nick's
root incident store before and after each declared fixture. Rows are written as
measured only when a new persisted incident is observed or the operator records
an observed prevention. Skipped and inconclusive rows remain pending.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "Validation/Replay/attack-techniques.json"
PROGRESS_DOC = ROOT / "DOCS" / "5.1-progress.md"
INCIDENTS = Path("/Library/Application Support/com.ehsanazish.nick/state/incidents.json")
START_MARKER = "<!-- installed-attack-scorecard:start -->"
END_MARKER = "<!-- installed-attack-scorecard:end -->"

INSTRUCTIONS = {
    "launch-agent-add": "Add the declared synthetic launch-agent fixture, then wait for Nick to persist it.",
    "launch-daemon-add": "Add the declared synthetic launch-daemon fixture.",
    "login-item-add": "Add the declared synthetic login-item fixture.",
    "cron-modification": "Apply the declared synthetic cron fixture.",
    "shell-profile-modification": "Modify only the declared scratch shell-profile fixture.",
    "download-to-shell": "Run the local no-op download-to-shell validation fixture.",
    "osascript-shell": "Run the declared harmless AppleScript-to-shell fixture.",
    "eicar-file": "Create the standard harmless EICAR test file in the scratch directory.",
    "downloaded-executable": "Run the declared local downloaded-executable fixture.",
    "system-binary-proxy": "Run the declared harmless proxy-execution fixture.",
    "keychain-dump-pattern": "Run the synthetic Keychain read/copy fixture; never use a real secret.",
    "browser-store-read": "Read the synthetic browser-store fixture from the unvalidated helper.",
    "ssh-key-read": "Read the synthetic private-key fixture; never use a real key.",
    "wallet-file-read": "Read the synthetic wallet fixture; never use real wallet data.",
    "gatekeeper-user-override": "Run the declared Gatekeeper override fixture against the scratch app.",
    "tcc-modification": "Run the declared synthetic TCC-change fixture.",
    "nick-tamper": "Run the documented Nick self-tamper validation fixture.",
    "permission-modification": "Change permissions only on the declared scratch fixture.",
    "protected-file-deletion": "Attempt the declared protected scratch-file deletion fixture.",
    "encoded-payload": "Run the declared harmless encoded-payload fixture.",
    "write-then-swap": "Run the declared random-byte write-then-swap scratch fixture.",
    "system-discovery": "Run the declared system-discovery fixture.",
    "process-discovery": "Run the declared process-discovery fixture.",
    "known-dangerous-destination": "Use the local/synthetic network reputation fixture; do not contact a live malicious host.",
}


def load_incident_fingerprints() -> dict[str, str]:
    data: Any = json.loads(INCIDENTS.read_text(encoding="utf-8"))
    found: dict[str, str] = {}

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            signals = value.get("contributingSignals")
            if isinstance(signals, list):
                encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
                identifier = str(value.get("id") or hashlib.sha256(encoded.encode()).hexdigest())
                reasons = sorted({
                    str(signal.get("context", {}).get("metadata", {}).get("reason", ""))
                    for signal in signals if isinstance(signal, dict)
                } - {""})
                found[identifier] = ", ".join(reasons) or str(value.get("title", "incident"))
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    return found


def update_progress(path: Path, techniques: list[dict[str, Any]], results: dict[str, dict[str, str]]) -> None:
    rows = [
        "## Installed ATT&CK replay — build 5062",
        "",
        f"Measured {datetime.now(timezone.utc).isoformat(timespec='seconds')}. Unmeasured rows remain pending; this table makes no rating claim.",
        "",
        "| ID | Technique | Result | Evidence |",
        "|---|---|---|---|",
    ]
    for technique in techniques:
        result = results.get(technique["id"], {"status": "pending", "evidence": "not measured"})
        evidence = result["evidence"].replace("|", "\\|").replace("\n", " ")
        rows.append(f"| {technique['id']} | {technique['name']} | {result['status']} | {evidence} |")
    block = START_MARKER + "\n" + "\n".join(rows) + "\n" + END_MARKER
    original = path.read_text(encoding="utf-8") if path.exists() else "# Nick 5.1 progress\n"
    if START_MARKER in original and END_MARKER in original:
        prefix, tail = original.split(START_MARKER, 1)
        _, suffix = tail.split(END_MARKER, 1)
        updated = prefix.rstrip() + "\n\n" + block + suffix
    else:
        updated = original.rstrip() + "\n\n" + block + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(updated, encoding="utf-8")


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo so the installed root incident store can be read.")
    if not INCIDENTS.is_file():
        raise SystemExit(f"Installed incident store not found: {INCIDENTS}")

    techniques = json.loads(MANIFEST.read_text(encoding="utf-8"))["techniques"]
    results: dict[str, dict[str, str]] = {}
    total = len(techniques)
    print(f"Nick installed {total}-technique replay. Use declared synthetic fixtures only.")
    for index, technique in enumerate(techniques, 1):
        print(f"\n[{index}/{total}] {technique['id']} — {technique['name']}")
        print(INSTRUCTIONS[technique["fixture"]])
        before = load_incident_fingerprints()
        action = input("Press Return after the fixture, or type s to leave pending / q to stop: ").strip().lower()
        if action == "q":
            break
        if action == "s":
            continue
        after = load_incident_fingerprints()
        new_ids = sorted(set(after) - set(before))
        if new_ids:
            evidence = "; ".join(f"{identifier}: {after[identifier]}" for identifier in new_ids)
            results[technique["id"]] = {"status": "alerted", "evidence": evidence}
            print("Measured: alerted")
            continue
        prevented = input("No new incident. Was prevention visibly confirmed? [y/N]: ").strip().lower() == "y"
        if prevented:
            note = input("Short evidence note: ").strip()
            results[technique["id"]] = {"status": "prevented", "evidence": note or "operator-observed prevention"}
        else:
            print("No persisted evidence; row remains pending (not marked missed).")

    update_progress(PROGRESS_DOC, techniques, results)
    print(f"\nWrote measured rows and pending placeholders to {PROGRESS_DOC}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
