#!/usr/bin/env python3
"""Guide and record the installed 24-technique replay without inventing results.

Run this script with sudo after installing the candidate. It snapshots Nick's
root incident store before and after each declared fixture. Rows are written as
measured only when a new persisted incident is observed or the operator records
an observed prevention. Skipped and completed-without-evidence outcomes are
recorded distinctly; neither is presented as a pass.
"""

from __future__ import annotations

import argparse
import hashlib
import base64
import json
import os
import plistlib
import pwd
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "Validation/Replay/attack-techniques.json"
PROGRESS_DOC = ROOT / "DOCS" / "5.1-progress.md"
INCIDENTS = Path("/Library/Application Support/com.ehsanazish.nick/state/incidents.json")
QUARANTINE_DB = Path("/Library/Application Support/com.ehsanazish.nick/quarantine.db")
THREAT_JOURNALS = (
    Path("/Library/Application Support/com.ehsanazish.nick/events/endpoint-events.json"),
    Path("/Library/Application Support/com.ehsanazish.nick/endpoint-events.json"),
)
START_MARKER = "<!-- installed-attack-scorecard:start -->"
END_MARKER = "<!-- installed-attack-scorecard:end -->"
EXPECTED_BUILD = "5069"
INSTALLED_APP_INFO = Path("/Applications/Nick.app/Contents/Info.plist")
SYSTEM_EXTENSIONS = Path("/usr/bin/systemextensionsctl")
EXPECTED_EXTENSIONS = (
    "com.ehsanazish.nick.NickExtension",
    "com.ehsanazish.nick.NickNetFilter",
)

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

# Expected persisted evidence. Alternatives are deliberate where macOS may
# report the same declared technique through BTM or FIM. A row passes only when
# one of these concrete reasons is newly persisted.
EXPECTED = {
    "T1543.001": ({"background-item-added", "file_integrity_created", "file_integrity_modified"}, {"review", "protected"}),
    "T1543.004": ({"background-item-added", "file_integrity_created", "file_integrity_modified"}, {"review", "protected"}),
    "T1547.015": ({"background-item-added"}, {"review"}),
    "T1053.003": ({"file_integrity_created", "file_integrity_modified", "cron_modification"}, {"review", "protected"}),
    "T1546.004": ({"shell_profile_modification", "file_integrity_modified"}, {"review", "protected"}),
    "T1059.004": ({"download_pipe_interpreter", "curl_pipe_shell", "wget_pipe_shell"}, {"protected"}),
    "T1059.002": ({"osascript_shell"}, {"review", "protected"}),
    "T1204.002": ({"eicar_test_file", "exact_hash_match", "yara_signature_match",
                    "eicar anti-malware test file", "eicar"}, {"protected"}),
    "T1105": ({"downloaded_executable", "quarantine_executable"}, {"review", "protected"}),
    "T1218": ({"system_binary_proxy"}, {"review", "protected"}),
    "T1555.001": ({"keychain_secret_read", "keychain_store_transfer", "keychain_command_correlation"}, {"review", "protected"}),
    "T1555.003": ({"credential_store_access"}, {"review", "protected"}),
    "T1552.004": ({"credential_store_access"}, {"review", "protected"}),
    "T1552.001": ({"credential_store_access"}, {"review", "protected"}),
    "T1553.001": ({"gatekeeper-user-override"}, {"review"}),
    "T1548.006": ({"tcc-permission-modified"}, {"review"}),
    "T1562.001": ({"endpoint_tamper_observed", "nick_tamper"}, {"protected"}),
    "T1222.002": ({"permission_modification"}, {"review", "protected"}),
    "T1070.004": ({"protected_file_deletion", "file_integrity_deleted"}, {"review", "protected"}),
    "T1027": ({"base64_payload", "encoded_payload", "decoded_payload_interpreter"}, {"review", "protected"}),
    "T1486": ({"ransomware_behavior", "mass_file_rename", "encrypted_atomic_replace"}, {"protected"}),
    "T1082": ({"system_discovery"}, {"review"}),
    "T1057": ({"process_discovery"}, {"review"}),
    "T1071.001": ({"known_dangerous_destination"}, {"review", "protected"}),
}
ROOT_FIXTURES = {"launch-daemon-add"}
INTERACTIVE_FIXTURES = {"tcc-modification"}
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def prepare_fixture_scratch(scratch: str, uid: int, gid: int) -> None:
    """Give the invoking user exclusive access to a root-created scratch dir."""
    if uid > 0:
        os.chown(scratch, uid, gid)
    os.chmod(scratch, 0o700)


def user_fixture_command(fixture: Path, scratch: str, user: str) -> list[str]:
    """Build the sudo invocation without relying on sudo preserving env."""
    return [
        "/usr/bin/sudo", "-H", "-u", user, "--", "/usr/bin/env",
        f"NICK_FIXTURE_ROOT={scratch}", str(fixture),
    ]


def decode_privileged_store(raw: bytes) -> Any:
    """Decode PrivilegedIncidentStoreRecord's JSON/base64 payload wrapper."""
    record = json.loads(raw.decode("utf-8"))
    if not isinstance(record, dict) or not isinstance(record.get("payload"), str):
        raise ValueError("incident store is not a PrivilegedIncidentStoreRecord")
    payload = base64.b64decode(record["payload"], validate=True)
    snapshot = json.loads(payload.decode("utf-8"))
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("incidents"), list):
        raise ValueError("privileged payload is not an incident snapshot")
    return snapshot


def incident_fingerprints_from_snapshot(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for incident in data.get("incidents", []):
        if not isinstance(incident, dict):
            continue
        alert = incident.get("alert", {})
        if not isinstance(alert, dict):
            continue
        signals = alert.get("contributingSignals", [])
        if not isinstance(signals, list):
            continue
        encoded = json.dumps(incident, sort_keys=True, separators=(",", ":"))
        identifier = str(incident.get("id") or alert.get("id") or hashlib.sha256(encoded.encode()).hexdigest())
        occurrence = max(1, int(alert.get("occurrenceCount", 1)))
        state = str(incident.get("state", "new"))
        metadata = [signal.get("metadata", signal.get("context", {}).get("metadata", {}))
                    for signal in signals if isinstance(signal, dict)]
        # Persisted signals carry both a detector rule and, for some families,
        # a more specific presentation reason. Preserve both: either may be
        # the scorecard's expected evidence and neither should mask the other.
        reasons = sorted({str(value) for item in metadata if isinstance(item, dict)
                          for value in (item.get("reason"), item.get("rule"))
                          if value})
        tiers = sorted({str(item.get("ruleTier") or "")
                        for item in metadata if isinstance(item, dict)} - {""})
        signal_severities = sorted({str(item.get("signalSeverity") or "")
                                    for item in metadata if isinstance(item, dict)} - {""})
        paths = sorted({str(signal.get("fileInfo", {}).get("path") or "")
                        for signal in signals if isinstance(signal, dict)
                        and isinstance(signal.get("fileInfo"), dict)
                        and signal.get("fileInfo", {}).get("path")})
        hashes = {str(signal.get("fileInfo", {}).get("sha256Hash") or "").lower()
                  for signal in signals if isinstance(signal, dict)
                  and isinstance(signal.get("fileInfo"), dict)}
        title = str(alert.get("title", "incident"))
        title_lower = title.lower()
        if "eicar" in title_lower or EICAR_SHA256 in hashes:
            reasons = sorted(set(reasons) | {
                "eicar", "eicar_test_file", "exact_hash_match",
            })
        found[f"{identifier}:{occurrence}:{state}"] = {
            "reasons": reasons,
            "tiers": tiers,
            "signalSeverities": signal_severities,
            "title": title,
            "paths": paths,
            "lastSeen": alert.get("lastSeen") or alert.get("timestamp"),
        }
    return found


def load_incident_fingerprints() -> dict[str, dict[str, Any]]:
    return incident_fingerprints_from_snapshot(decode_privileged_store(INCIDENTS.read_bytes()))


def prevention_fingerprints() -> dict[str, dict[str, str]]:
    """Read durable prevention evidence from its authoritative stores."""
    found: dict[str, dict[str, str]] = {}
    if QUARANTINE_DB.is_file():
        with sqlite3.connect(f"file:{QUARANTINE_DB}?mode=ro", uri=True) as database:
            for row in database.execute(
                "SELECT id, original_path, quarantined_path, threat_name, quarantined_at "
                "FROM quarantine"
            ):
                identifier, original, quarantined, threat, timestamp = map(str, row)
                found[f"quarantine:{identifier}"] = {
                    "kind": "quarantine", "target": original,
                    "detail": f"{threat}; moved to {quarantined}; {timestamp}",
                }
    for journal in THREAT_JOURNALS:
        if not journal.is_file():
            continue
        try:
            envelopes = json.loads(journal.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for envelope in envelopes if isinstance(envelopes, list) else []:
            if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), str):
                continue
            try:
                payload = json.loads(base64.b64decode(envelope["payload"], validate=True))
            except (ValueError, TypeError, json.JSONDecodeError):
                continue
            identifier = str(envelope.get("id") or hashlib.sha256(envelope["payload"].encode()).hexdigest())
            kind = str(envelope.get("kind", ""))
            if kind == "remediation":
                for index, action in enumerate(payload.get("actions", [])):
                    if isinstance(action, dict) and action.get("success") is True:
                        found[f"remediation:{identifier}:{index}"] = {
                            "kind": str(action.get("type", "remediation")),
                            "target": str(action.get("target") or payload.get("threatPath") or ""),
                            "detail": str(action.get("detail") or payload.get("threatName") or ""),
                        }
            elif kind == "endpointEvent" and str(payload.get("decision", "")).lower() == "deny":
                found[f"auth-deny:{identifier}"] = {
                    "kind": "AUTH deny",
                    "target": str(payload.get("filePath") or payload.get("processPath") or ""),
                    "detail": str(payload.get("threatName") or payload.get("eventType") or "denied"),
                }
    return found


def matching_prevention(
    before: dict[str, dict[str, str]],
    after: dict[str, dict[str, str]],
    incident: dict[str, Any],
) -> dict[str, str] | None:
    paths = {os.path.realpath(path) for path in incident.get("paths", []) if path}
    for identifier in sorted(set(after) - set(before)):
        record = after[identifier]
        target = record.get("target", "")
        canonical = os.path.realpath(target) if target else ""
        if not paths or canonical in paths:
            return record
    return None


def measured_status(prevention: dict[str, str] | None) -> str:
    """A process exit is not proof that Nick prevented the technique."""
    return "PREVENTED" if prevention is not None else "PASS"


def installed_app_build(info_plist: Path = INSTALLED_APP_INFO) -> str:
    """Read the installed app build without trusting the checkout version."""
    try:
        with info_plist.open("rb") as stream:
            value = plistlib.load(stream).get("CFBundleVersion")
    except (OSError, plistlib.InvalidFileException) as error:
        raise RuntimeError(f"could not read installed Nick build from {info_plist}: {error}") from error
    if not isinstance(value, (str, int)) or not str(value).isdigit():
        raise RuntimeError(f"installed Nick CFBundleVersion is missing or invalid in {info_plist}")
    return str(value)


def active_extension_builds(output: str) -> dict[str, str]:
    """Extract only activated+enabled Nick system-extension builds."""
    builds: dict[str, str] = {}
    for line in output.splitlines():
        if "[activated enabled]" not in line:
            continue
        for bundle_id in EXPECTED_EXTENSIONS:
            if bundle_id not in line:
                continue
            match = re.search(r"\([^/()]+/(\d+)\)", line)
            if match:
                builds[bundle_id] = match.group(1)
    return builds


def installed_build_header(
    info_plist: Path = INSTALLED_APP_INFO,
    systemextensionsctl: Path = SYSTEM_EXTENSIONS,
) -> tuple[str, dict[str, str]]:
    """Read and validate the installed app and both active extension builds."""
    app_build = installed_app_build(info_plist)
    completed = subprocess.run(
        [str(systemextensionsctl), "list"], check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"systemextensionsctl list failed ({completed.returncode}): {completed.stdout.strip()}"
        )
    extension_builds = active_extension_builds(completed.stdout)
    missing = [bundle_id for bundle_id in EXPECTED_EXTENSIONS if bundle_id not in extension_builds]
    if missing:
        raise RuntimeError("active Nick system extension not found: " + ", ".join(missing))

    actual = {"Nick.app": app_build, **extension_builds}
    mismatches = [f"{component}={build}" for component, build in actual.items()
                  if build != EXPECTED_BUILD]
    if mismatches:
        raise RuntimeError(
            f"recorder expects build {EXPECTED_BUILD}, but installed components differ: "
            + ", ".join(mismatches)
        )
    return app_build, extension_builds


def update_progress(techniques: list[dict[str, Any]], results: dict[str, dict[str, str]]) -> None:
    rows = [
        f"## Installed ATT&CK replay — build {EXPECTED_BUILD}",
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
    original = PROGRESS_DOC.read_text(encoding="utf-8") if PROGRESS_DOC.exists() else "# Nick 5.1 progress\n"
    if START_MARKER in original and END_MARKER in original:
        prefix, tail = original.split(START_MARKER, 1)
        _, suffix = tail.split(END_MARKER, 1)
        updated = prefix.rstrip() + "\n\n" + block + suffix
    else:
        updated = original.rstrip() + "\n\n" + block + "\n"
    PROGRESS_DOC.parent.mkdir(parents=True, exist_ok=True)
    PROGRESS_DOC.write_text(updated, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="print every fixture and expected evidence")
    parser.add_argument(
        "--inspect-store", action="store_true",
        help="decode a store supplied on standard input and print recorder fingerprints"
    )
    args = parser.parse_args()
    if args.inspect_store:
        print(json.dumps(
            incident_fingerprints_from_snapshot(decode_privileged_store(sys.stdin.buffer.read())),
            sort_keys=True
        ))
        return 0
    techniques = json.loads(MANIFEST.read_text(encoding="utf-8"))["techniques"]
    if args.dry_run:
        for index, technique in enumerate(techniques, 1):
            reasons, tiers = EXPECTED[technique["id"]]
            print(f"{index:02d}. {technique['id']} {technique['name']}")
            print(f"    fixture: Scripts/fixtures/{technique['fixture']}.sh")
            print(f"    expected rule: {', '.join(sorted(reasons))}; tier: {', '.join(sorted(tiers))}")
            print(f"    {INSTRUCTIONS[technique['fixture']]}")
        return 0
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo so the installed root incident store can be read.")
    if not INCIDENTS.is_file():
        raise SystemExit(f"Installed incident store not found: {INCIDENTS}")

    try:
        app_build, extension_builds = installed_build_header()
    except RuntimeError as error:
        raise SystemExit(f"Installed build check failed: {error}") from error

    results: dict[str, dict[str, str]] = {}
    total = len(techniques)
    print(f"Expected recorder build: {EXPECTED_BUILD}")
    print(f"Installed Nick.app build: {app_build}")
    for bundle_id in EXPECTED_EXTENSIONS:
        print(f"Active {bundle_id} build: {extension_builds[bundle_id]}")
    print(f"Nick installed {total}-technique replay. Use declared synthetic fixtures only.")
    for index, technique in enumerate(techniques, 1):
        print(f"\n[{index}/{total}] {technique['id']} — {technique['name']}")
        fixture_name = technique["fixture"]
        print(INSTRUCTIONS[fixture_name])
        before = load_incident_fingerprints()
        prevention_before = prevention_fingerprints()
        action = input("Run? [Y/n], s to leave pending, q to stop: ").strip().lower()
        if action == "q":
            break
        if action in {"n", "s"}:
            results[technique["id"]] = {
                "status": "SKIPPED",
                "evidence": "operator skipped the declared fixture",
            }
            continue
        fixture = (ROOT / "Scripts" / "fixtures" / f"{fixture_name}.sh").resolve()
        fixtures_root = (ROOT / "Scripts" / "fixtures").resolve()
        if fixture.parent != fixtures_root or not fixture.is_file():
            print("Fixture is missing; row remains pending.")
            continue
        started = time.time()
        manual_completed = False
        fixture_returncode = 0
        with tempfile.TemporaryDirectory(prefix="nick-scorecard-") as scratch:
            environment = os.environ.copy()
            environment["NICK_FIXTURE_ROOT"] = scratch
            uid = int(os.environ.get("SUDO_UID", "0"))
            gid = int(os.environ.get("SUDO_GID", "0"))
            prepare_fixture_scratch(scratch, uid, gid)
            if uid > 0 and fixture_name not in ROOT_FIXTURES:
                user = pwd.getpwuid(uid).pw_name
                command = user_fixture_command(fixture, scratch, user)
            else:
                command = [str(fixture)]
            interactive = fixture_name in INTERACTIVE_FIXTURES
            completed = subprocess.run(
                command, env=environment, check=False, text=True,
                stdout=None if interactive else subprocess.PIPE,
                stderr=None if interactive else subprocess.STDOUT,
                timeout=60,
            )
            fixture_returncode = completed.returncode
            if completed.stdout:
                print(completed.stdout.rstrip())
            if completed.returncode == 64:
                manual_action = input("Complete the printed manual steps, then press Enter; s to skip: ").strip().lower()
                if manual_action == "s":
                    results[technique["id"]] = {
                        "status": "SKIPPED",
                        "evidence": "operator skipped the manual fixture",
                    }
                    continue
                manual_completed = True
            elif completed.returncode != 0:
                print(
                    f"Fixture exited {completed.returncode}; checking the durable store "
                    "because prevention may have stopped it."
                )
            time.sleep(3)
        after = load_incident_fingerprints()
        prevention_after = prevention_fingerprints()
        new_ids = sorted(set(after) - set(before))
        expected_reasons, expected_tiers = EXPECTED[technique["id"]]
        matches = []
        for identifier in new_ids:
            record = after[identifier]
            reasons = set(record["reasons"])
            tiers = set(record["tiers"])
            if reasons.intersection(expected_reasons) and (not tiers or tiers.intersection(expected_tiers)):
                matches.append((identifier, record))
        if matches:
            latency = time.time() - started
            identifier, record = matches[0]
            rule = sorted(set(record["reasons"]).intersection(expected_reasons))[0]
            tier = sorted(set(record["tiers"]).intersection(expected_tiers))[0] if record["tiers"] else "not recorded"
            evidence = f"{identifier}; rule={rule}; tier={tier}; observed<= {latency:.2f}s"
            prevention = matching_prevention(prevention_before, prevention_after, record)
            status = measured_status(prevention)
            if prevention is not None:
                evidence += f"; prevention={prevention['kind']} target={prevention['target']}"
            results[technique["id"]] = {"status": status, "evidence": evidence}
            print(f"Measured: {status} ({rule}, {tier}, <= {latency:.2f}s)")
            continue
        if new_ids:
            seen = sorted({reason for identifier in new_ids for reason in after[identifier]["reasons"]})
            print(f"New evidence did not match the expected rule ({', '.join(seen) or 'no rule recorded'}); row remains pending.")
        status = "MANUAL DONE: NO EVIDENCE" if manual_completed else "RAN: NO EVIDENCE"
        results[technique["id"]] = {
            "status": status,
            "evidence": (
                f"fixture exited {fixture_returncode}; no matching persisted evidence"
                if fixture_returncode != 0 else "no matching persisted evidence"
            ),
        }
        print(f"No matching persisted evidence; recorded as {status}.")

    update_progress(techniques, results)
    print(f"\nWrote measured rows and pending placeholders to {PROGRESS_DOC}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
