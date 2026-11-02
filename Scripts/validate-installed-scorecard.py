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
import stat
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
FULL_START_MARKER = "<!-- installed-full-scorecard:start -->"
FULL_END_MARKER = "<!-- installed-full-scorecard:end -->"
EXPECTED_BUILD = "5084"
SETTINGS = Path("/Library/Application Support/com.ehsanazish.nick/state/settings.json")
SIGNATURE_DB = Path("/Library/Application Support/com.ehsanazish.nick/signatures.db")
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
    "file-deletion": "Create an inert LaunchAgent as your user; the recorder waits for durable creation evidence, then asks the fixture to delete it.",
    "encoded-payload": "Run the declared harmless encoded-payload fixture.",
    "write-then-swap": "Run the declared random-byte write-then-swap scratch fixture.",
    "system-discovery": "Run the declared system-discovery fixture.",
    "process-discovery": "Run the declared process-discovery fixture.",
    "known-dangerous-destination": "Connect only to Nick's harmless signed web canary; no live malicious host is contacted.",
}

# Expected persisted evidence. Alternatives are deliberate where macOS may
# report the same declared technique through BTM or FIM. A row passes only when
# one of these concrete reasons is newly persisted.
LOGIN_ITEMS_TECHNIQUE = "T1547.015"
NOT_MEASURED = "not measured"
FIELD_EVIDENCE_STATUS = "PASS (field evidence)"

EXPECTED = {
    "T1543.001": ({"background-item-added", "file_integrity_created", "file_integrity_modified"}, {"review", "protected"}),
    "T1543.004": ({"background-item-added", "file_integrity_created", "file_integrity_modified"}, {"review", "protected"}),
    LOGIN_ITEMS_TECHNIQUE: ({"background-item-added"}, {"review"}),
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
    # The reversible fixture revokes a third-party Apple Events grant. The
    # 5069 TCC policy intentionally records that as inform/observed; sensitive
    # grants and Nick permission loss remain review-tier.
    "T1548.006": ({"tcc-permission-modified"}, {"review", "observed"}),
    "T1562.001": ({"endpoint_tamper_observed", "nick_tamper", "nick_unexpected_exit"}, {"protected"}),
    "T1222.002": ({"permission_modification"}, {"review", "protected"}),
    "T1070.004": ({"protected_file_deletion", "file_integrity_deleted"}, {"review", "protected"}),
    "T1027": ({"base64_payload", "encoded_payload", "decoded_payload_interpreter"}, {"review", "protected"}),
    "T1486": ({"ransomware_behavior", "mass_file_rename", "encrypted_atomic_replace"}, {"protected"}),
    "T1082": ({"system_discovery"}, {"review"}),
    "T1057": ({"process_discovery"}, {"review"}),
    # This harmless HTTPS endpoint is classified only by NICK_CANARY_WEB from
    # a verified signed payload. Its inform tier proves reputation delivery
    # without inflating threat totals or contacting a malicious host.
    "T1071.001": ({"NICK_CANARY_WEB", "nick_test_indicator"}, {"inform"}),
}
ROOT_FIXTURES = {"launch-daemon-add"}
INTERACTIVE_FIXTURES = {"tcc-modification"}
DETECTION_ONLY_TECHNIQUES = {"T1070.004"}
MAPPING_REVIEW_TECHNIQUES = {
    LOGIN_ITEMS_TECHNIQUE, "T1218", "T1222.002", "T1082", "T1057", "T1071.001",
}
MANDATORY_TECHNIQUE_FAMILIES = {
    "tampering with Nick": {"T1562.001"},
    "credential access": {"T1555.001", "T1555.003", "T1552.004", "T1552.001"},
    "persistence": {"T1543.001", "T1543.004", LOGIN_ITEMS_TECHNIQUE, "T1053.003", "T1546.004"},
    "download-to-shell": {"T1059.004"},
}
COMPLETED_STATUSES = {"PASS", "PREVENTED", "DETECTED", FIELD_EVIDENCE_STATUS}
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


class FixtureLineage:
    """Process identity observed while one declared fixture was running."""

    def __init__(self, root_pid: int, pids: set[int] | None = None):
        self.root_pid = root_pid
        self.pids = set(pids or ())
        self.process_groups: set[int] = set()
        self.sessions: set[int] = set()

    def includes(self, record: dict[str, Any]) -> bool:
        process_ids = set(record.get("processIDs", []))
        parent_ids = set(record.get("parentPIDs", []))
        groups = set(record.get("processGroupIDs", []))
        sessions = set(record.get("sessionIDs", []))
        return bool(
            process_ids.intersection(self.pids)
            or parent_ids.intersection(self.pids)
            or groups.intersection(self.process_groups)
            # A login session contains many unrelated processes.  Session
            # identity is supporting evidence only; a shared process group is
            # still required before it can establish fixture lineage.
            or (
                groups.intersection(self.process_groups)
                and sessions.intersection(self.sessions)
            )
        )


def prepare_fixture_scratch(scratch: str, uid: int, gid: int) -> None:
    """Give the invoking user exclusive access to a root-created scratch dir."""
    if uid > 0:
        os.chown(scratch, uid, gid)
    os.chmod(scratch, 0o700)


def user_fixture_command(fixture: Path, scratch: str, user: str) -> list[str]:
    """Build the sudo invocation without relying on sudo preserving env."""
    user_home = pwd.getpwnam(user).pw_dir
    return [
        "/usr/bin/sudo", "-H", "-u", user, "--", "/usr/bin/env",
        f"NICK_FIXTURE_ROOT={scratch}",
        f"NICK_FIXTURE_USER={user}",
        f"NICK_FIXTURE_HOME={user_home}",
        str(fixture),
    ]


def console_user_fixture_command(fixture: Path, scratch: str, user: str, uid: int) -> list[str]:
    """Run a GUI fixture in the logged-in user's launchd session."""
    return [
        "/bin/launchctl", "asuser", str(uid),
        *user_fixture_command(fixture, scratch, user),
    ]


def process_snapshot() -> dict[int, tuple[int, int, int]]:
    """Return pid -> (ppid, process group, session) without trusting names."""
    completed = subprocess.run(
        ["/bin/ps", "-axo", "pid=,ppid=,pgid=,sess="],
        check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    )
    if completed.returncode != 0:
        return {}
    snapshot: dict[int, tuple[int, int, int]] = {}
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) != 4 or not all(part.lstrip("-").isdigit() for part in parts):
            continue
        pid, ppid, group, session = map(int, parts)
        snapshot[pid] = (ppid, group, session)
    return snapshot


def extend_fixture_lineage(lineage: FixtureLineage, snapshot: dict[int, tuple[int, int, int]]) -> None:
    """Add descendants of the fixture root, including short-lived intermediates."""
    lineage.pids.add(lineage.root_pid)
    changed = True
    while changed:
        changed = False
        for pid, (parent, group, session) in snapshot.items():
            if pid in lineage.pids or parent not in lineage.pids:
                continue
            lineage.pids.add(pid)
            changed = True

    for pid in lineage.pids:
        values = snapshot.get(pid)
        if values is None:
            continue
        _, group, session = values
        if group > 0:
            lineage.process_groups.add(group)
        if session > 0:
            lineage.sessions.add(session)


def run_fixture_with_lineage(
    command: list[str], environment: dict[str, str], interactive: bool, timeout: float = 60,
) -> tuple[subprocess.CompletedProcess[str], FixtureLineage]:
    """Run a fixture and sample its pid/pgid/session lineage while it is alive."""
    process = subprocess.Popen(
        command,
        env=environment,
        text=True,
        stdout=None if interactive else subprocess.PIPE,
        stderr=None if interactive else subprocess.STDOUT,
    )
    lineage = FixtureLineage(root_pid=process.pid, pids={process.pid})
    deadline = time.monotonic() + timeout
    while process.poll() is None and time.monotonic() < deadline:
        extend_fixture_lineage(lineage, process_snapshot())
        time.sleep(0.02)
    if process.poll() is None:
        process.kill()
        stdout, _ = process.communicate()
        raise subprocess.TimeoutExpired(command, timeout, output=stdout)
    extend_fixture_lineage(lineage, process_snapshot())
    stdout, _ = process.communicate()
    return subprocess.CompletedProcess(command, process.returncode, stdout, None), lineage


def decode_privileged_payload(raw: bytes) -> Any:
    """Decode the authenticated root-store JSON/base64 payload wrapper."""
    record = json.loads(raw.decode("utf-8"))
    if not isinstance(record, dict) or not isinstance(record.get("payload"), str):
        raise ValueError("store is not a PrivilegedIncidentStoreRecord")
    payload = base64.b64decode(record["payload"], validate=True)
    return json.loads(payload.decode("utf-8"))


def decode_privileged_store(raw: bytes) -> Any:
    """Decode and validate the incident snapshot payload."""
    snapshot = decode_privileged_payload(raw)
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
        correlation_values = sorted({str(value) for item in metadata if isinstance(item, dict)
                                     for key in ("launchItemLabel", "persistencePath", "indicatorID")
                                     for value in (item.get(key),) if value})
        # Persisted signals carry both a detector rule and, for some families,
        # a more specific presentation reason. Preserve both: either may be
        # the scorecard's expected evidence and neither should mask the other.
        reasons = sorted({str(value) for item in metadata if isinstance(item, dict)
                          for value in (item.get("reason"), item.get("rule"), item.get("appleEvent"))
                          if value})
        tiers = sorted({str(item.get("ruleTier") or "")
                        for item in metadata if isinstance(item, dict)} - {""})
        signal_severities = sorted({str(item.get("signalSeverity") or "")
                                    for item in metadata if isinstance(item, dict)} - {""})
        file_paths = {str(signal.get("fileInfo", {}).get("path") or "")
                      for signal in signals if isinstance(signal, dict)
                      and isinstance(signal.get("fileInfo"), dict)
                      and signal.get("fileInfo", {}).get("path")}
        # BTM launch-item events persist the affected item in signal metadata
        # rather than fileInfo. Treat it as path evidence so the recorder can
        # correlate the exact randomized fixture app without weakening the
        # process-lineage requirement used by other techniques.
        persistence_paths = {str(item.get("persistencePath") or "")
                             for item in metadata if isinstance(item, dict)
                             and item.get("persistencePath")}
        paths = sorted(file_paths | persistence_paths)
        process_infos = [signal.get("processInfo", {}) for signal in signals
                         if isinstance(signal, dict) and isinstance(signal.get("processInfo"), dict)]
        def integer_values(*keys: str) -> list[int]:
            values: set[int] = set()
            for item in [*metadata, *process_infos]:
                if not isinstance(item, dict):
                    continue
                for key in keys:
                    value = item.get(key)
                    if isinstance(value, int) and value > 0:
                        values.add(value)
                    elif isinstance(value, str) and value.isdigit() and int(value) > 0:
                        values.add(int(value))
            return sorted(values)
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
            "processIDs": integer_values("pid", "actorPID", "responsiblePID"),
            "parentPIDs": integer_values("parentPID", "ppid"),
            "processGroupIDs": integer_values("processGroupID", "processGroup", "pgid"),
            "sessionIDs": integer_values("sessionID", "session"),
            "correlationValues": correlation_values,
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


def measured_status(
    prevention: dict[str, str] | None,
    technique_id: str | None = None,
) -> str:
    """A process exit is not proof that Nick prevented the technique."""
    if technique_id in DETECTION_ONLY_TECHNIQUES:
        return "DETECTED"
    return "PREVENTED" if prevention is not None else "PASS"


def matching_incidents(
    before: dict[str, dict[str, Any]],
    after: dict[str, dict[str, Any]],
    expected_reasons: set[str],
    expected_tiers: set[str],
    expected_path: str | None = None,
    fixture_lineage: FixtureLineage | None = None,
    expected_correlation_value: str | None = None,
) -> list[tuple[str, dict[str, Any]]]:
    """Return only newly persisted occurrences matching this replay row."""
    matches: list[tuple[str, dict[str, Any]]] = []
    for identifier in sorted(set(after) - set(before)):
        record = after[identifier]
        reasons = set(record["reasons"])
        tiers = set(record["tiers"])
        # Endpoint Security reports resolved paths (`/private/tmp/...`) while
        # fixtures may be launched through the user-facing `/tmp` symlink.
        # Compare canonical paths so the same file is not rejected solely due
        # to that macOS path alias.
        paths = {os.path.realpath(path) for path in record.get("paths", []) if path}
        path_matches = expected_path is None or os.path.realpath(expected_path) in paths
        lineage_matches = fixture_lineage is None or fixture_lineage.includes(record)
        correlation_matches = expected_correlation_value is None or (
            expected_correlation_value in set(record.get("correlationValues", []))
        )
        if reasons.intersection(expected_reasons) and (
            not tiers or tiers.intersection(expected_tiers)
        ) and path_matches and lineage_matches and correlation_matches:
            matches.append((identifier, record))
    return matches


def wait_for_matching_incidents(
    before: dict[str, dict[str, Any]],
    expected_reasons: set[str],
    expected_tiers: set[str],
    expected_path: str | None = None,
    fixture_lineage: FixtureLineage | None = None,
    expected_correlation_value: str | None = None,
    timeout: float = 15.0,
    poll_interval: float = 0.5,
) -> tuple[dict[str, dict[str, Any]], list[tuple[str, dict[str, Any]]]]:
    """Poll the durable store because app ingestion can trail a fixture.

    A fixed sleep caused one row's evidence to arrive during the next row and
    be reported as unrelated noise. Polling remains bounded and succeeds only
    for a concrete expected machine rule and tier.
    """
    deadline = time.monotonic() + timeout
    after = load_incident_fingerprints()
    while True:
        matches = matching_incidents(
            before, after, expected_reasons, expected_tiers, expected_path, fixture_lineage,
            expected_correlation_value
        )
        if matches or time.monotonic() >= deadline:
            return after, matches
        time.sleep(poll_interval)
        after = load_incident_fingerprints()


def describe_new_occurrences(
    before: dict[str, dict[str, Any]],
    after: dict[str, dict[str, Any]],
    fixture_lineage: FixtureLineage | None,
) -> None:
    """Print every new occurrence so a mapping review cannot hide noise."""
    new_ids = sorted(set(after) - set(before))
    if not new_ids:
        print("Occurrence review: no new durable occurrence appeared in the row window.")
        return
    print("Occurrence review (new durable evidence in this row window):")
    for identifier in new_ids:
        record = after[identifier]
        lineage = "match" if fixture_lineage and fixture_lineage.includes(record) else "no match"
        if fixture_lineage is None:
            lineage = "not required"
        print(
            "  - " + identifier
            + f"; rules={','.join(record['reasons']) or 'none'}"
            + f"; tiers={','.join(record['tiers']) or 'none'}"
            + f"; pids={','.join(map(str, record.get('processIDs', []))) or 'none'}"
            + f"; lineage={lineage}"
        )


def strict_mode_configuration(settings_path: Path = SETTINGS) -> tuple[bool, bool]:
    snapshot = decode_privileged_payload(settings_path.read_bytes())
    if not isinstance(snapshot, dict):
        raise ValueError("settings payload is not an object")
    return bool(snapshot.get("strictModeEnabled")), bool(snapshot.get("blockingKillSwitch"))


def run_file_deletion_replay(
    fixture: Path,
    scratch: str,
    user: str,
    before: dict[str, dict[str, Any]],
    started: float,
) -> dict[str, str]:
    """Drive the user file operations around root-store evidence polling."""
    target = str(
        Path(pwd.getpwnam(user).pw_dir)
        / "Library/LaunchAgents/com.ehsanazish.nick.fixture.deletion.plist"
    )
    marker = Path(scratch) / "file-deletion-phase2"
    process = subprocess.Popen(
        user_fixture_command(fixture, scratch, user),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    creation_after: dict[str, dict[str, Any]] = before
    creation_matches: list[tuple[str, dict[str, Any]]] = []
    output = ""
    try:
        creation_after, creation_matches = wait_for_matching_incidents(
            before,
            {"file_integrity_created"},
            {"review", "protected"},
            expected_path=target,
            timeout=30,
        )
        marker.touch(exist_ok=True)
        try:
            output, _ = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            pass
    finally:
        marker.touch(exist_ok=True)
        if process.poll() is None:
            process.terminate()
            try:
                trailing, _ = process.communicate(timeout=5)
                output += trailing or ""
            except subprocess.TimeoutExpired:
                process.kill()
                trailing, _ = process.communicate()
                output += trailing or ""
    if output.strip():
        print(output.rstrip())

    reminder = (
        "Reminder: the created and deleted findings remain pending for you "
        "to acknowledge in Nick; the recorder did not acknowledge them."
    )
    if not creation_matches:
        print("Creation was not detected within 30 seconds; cleanup still ran.")
        print(reminder)
        return {"status": "FAIL", "evidence": "creation not detected"}

    _, deletion_matches = wait_for_matching_incidents(
        creation_after,
        {"file_integrity_deleted"},
        {"review", "protected"},
        expected_path=target,
        timeout=30,
    )
    print(reminder)
    if not deletion_matches:
        return {
            "status": "FAIL",
            "evidence": "creation detected as expected; deletion not detected",
        }

    created_id, created = creation_matches[0]
    deleted_id, deleted = deletion_matches[0]
    tier = min(set(deleted["tiers"]).intersection({"review", "protected"}))
    latency = time.time() - started
    return {
        "status": "DETECTED",
        "evidence": (
            f"created={created_id} (expected evidence, tier="
            f"{','.join(created['tiers']) or 'not recorded'}); "
            f"deleted={deleted_id}; rule=file_integrity_deleted; "
            f"tier={tier}; observed<= {latency:.2f}s"
        ),
    }


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
        result = results.get(technique["id"], {"status": "pending", "evidence": NOT_MEASURED})
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


def read_external_manifest(path: Path) -> tuple[Path, bytes]:
    """Read one bounded, non-symlink regular file supplied by the operator."""
    resolved = path.expanduser().resolve(strict=True)
    descriptor = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise ValueError(f"hash manifest is not a regular file: {resolved}")
        if status.st_size > 64 * 1024 * 1024:
            raise ValueError("hash manifest exceeds the 64 MiB limit")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return resolved, stream.read()
    finally:
        os.close(descriptor)


def manifest_entries(value: Any, raw: str) -> tuple[str | None, list[Any]]:
    if isinstance(value, dict):
        return value.get("source"), value.get("samples") or value.get("hashes") or []
    if isinstance(value, list):
        return None, value
    return None, [line.strip().split()[0] for line in raw.splitlines() if line.strip()]


def manifest_hashes(path: Path, manifest_data: bytes) -> tuple[str, set[str]]:
    """Read external hash-only JSON/JSONL/text without touching samples."""
    raw = manifest_data.decode("utf-8")
    source = path.name
    hashes: set[str] = set()
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        value = None
    declared_source, entries = manifest_entries(value, raw)
    source = str(declared_source or source)
    for entry in entries:
        digest = entry.get("sha256") if isinstance(entry, dict) else entry
        if isinstance(digest, str):
            hashes.add(digest.lower())
    invalid = sorted(item for item in hashes if re.fullmatch(r"[0-9a-f]{64}", item) is None)
    if invalid:
        raise ValueError(f"manifest contains {len(invalid)} invalid SHA-256 value(s)")
    if not hashes:
        raise ValueError("manifest contains no SHA-256 hashes")
    if "eset" in source.lower() or "eset" in path.name.lower():
        raise ValueError("the ESET source set is not an independent measurement set")
    return source, hashes


def replay_hash_manifest(path: Path, database_path: Path = SIGNATURE_DB) -> dict[str, str]:
    resolved, manifest_data = read_external_manifest(path)
    source, hashes = manifest_hashes(resolved, manifest_data)
    if not database_path.is_file():
        raise ValueError(f"installed signature database not found: {database_path}")
    placeholders = ",".join("?" for _ in hashes)
    with sqlite3.connect(f"file:{database_path}?mode=ro", uri=True) as database:
        rows = database.execute(
            f"SELECT hash FROM signatures WHERE hash IN ({placeholders})", sorted(hashes)
        )
        alerted = {str(row[0]).lower() for row in rows}
    percent = 100.0 * len(alerted) / len(hashes)
    return {
        "source": source,
        "total": str(len(hashes)),
        "alerted": str(len(alerted)),
        "percentage": f"{percent:.2f}%",
        "manifestSHA256": hashlib.sha256(manifest_data).hexdigest(),
    }


def attack_scorecard_summary(
    techniques: list[dict[str, Any]], results: dict[str, dict[str, str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str, str, str]:
    successes = [item for item in techniques
                 if results.get(item["id"], {}).get("status") in COMPLETED_STATUSES]
    prevented = [item for item in techniques
                 if results.get(item["id"], {}).get("status") == "PREVENTED"]
    evidence_ids = [
        results[item["id"]]["evidence"].split(";", 1)[0]
        for item in successes if results[item["id"]].get("evidence")
    ]
    successful_ids = {item["id"] for item in successes}
    missing = {
        family: sorted(ids - successful_ids)
        for family, ids in MANDATORY_TECHNIQUE_FAMILIES.items()
        if ids - successful_ids
    }
    if not missing:
        return successes, prevented, ", ".join(evidence_ids) or NOT_MEASURED, \
            "all mandatory rows alerted", "all pinned mandatory-family rows have measured evidence"
    evidence = "; ".join(
        f"{family}: {', '.join(ids)} not measured" for family, ids in missing.items()
    )
    return successes, prevented, ", ".join(evidence_ids) or NOT_MEASURED, \
        "mandatory incomplete", evidence


def full_scorecard_rows(
    techniques: list[dict[str, Any]],
    results: dict[str, dict[str, str]],
    hash_result: dict[str, str] | None = None,
) -> list[str]:
    successes, prevented, attack_evidence, mandatory_result, mandatory_evidence = \
        attack_scorecard_summary(techniques, results)
    hash_current = NOT_MEASURED
    hash_evidence = NOT_MEASURED
    if hash_result:
        hash_current = f"{hash_result['percentage']} alerted ({hash_result['alerted']}/{hash_result['total']})"
        hash_evidence = f"manifest sha256 {hash_result['manifestSHA256']}; source {hash_result['source']}"
    attack_percent = 100.0 * len(successes) / 24
    prevention_percent = 100.0 * len(prevented) / 24
    return [
        "## 5.1 scorecard — installed evidence",
        "",
        "| Metric | 4/10 target (settle) | 1/10 stretch (aim) | Current result | Evidence |",
        "|---|---|---|---|---|",
        f"| Known families — hash/signature (versioned, deduplicated manifest) | ≥ 90% alerted | ≥ 98% | {hash_current} | {hash_evidence} |",
        "| Known families — behaviour only (hash rules off) | ≥ 60% (set real number after 5.0.1 baseline) | ≥ 85% | not measured | not measured — requires a disposable VM behaviour run |",
        f"| ATT&CK for macOS, 24 pinned techniques | ≥ 80% alerted; all mandatory alerted; ≥ 25% preventable (strict mode) | 100% alerted; ≥ 60% preventable | {len(successes)}/24 alerted ({attack_percent:.2f}%); {len(prevented)}/24 prevented ({prevention_percent:.2f}%); {mandatory_result} | {attack_evidence}; {mandatory_evidence} |",
        "| Root: extension stopped, app alive | alert ≤ 60 s | ≤ 10 s | pending | not measured; manual steps: keep Nick open; find the endpoint PID with `pgrep -f '/Library/SystemExtensions/.*/com.ehsanazish.nick.NickExtension.systemextension/Contents/MacOS/com.ehsanazish.nick.NickExtension'`; verify `ps -p <PID> -o command=`; run `sudo kill -9 <PID>`; wait up to 60 s; record the persisted incident ID and timestamps; confirm relaunch |",
        "| Root: extension and app both gone | gap reported on next start, every run | gap includes the bounded interruption window and corroborating local evidence | pending | not measured; manual steps: record T1; verify and stop the endpoint PID as above; immediately Force Quit Nick; wait 60 s; reopen `/Applications/Nick.app`; record the persisted gap incident, T2, and bounded interval; confirm reconnection |",
        "| False positives, ≥ 40 active workload hours, fixed manifest, counted per incident key | ≤ 1 review-tier, 0 protected | 0 | not measured | not measured for build 5081 |",
        "| ES health | p99 < 100 ms, 0 deadline misses, 0 acks without persistence | p99 < 30 ms | not measured | not measured for build 5081 |",
    ]


def update_full_scorecard(
    techniques: list[dict[str, Any]], results: dict[str, dict[str, str]],
    hash_result: dict[str, str] | None = None,
) -> None:
    block = FULL_START_MARKER + "\n" + "\n".join(
        full_scorecard_rows(techniques, results, hash_result)
    ) + "\n" + FULL_END_MARKER
    original = PROGRESS_DOC.read_text(encoding="utf-8") if PROGRESS_DOC.exists() else "# Nick 5.1 progress\n"
    if FULL_START_MARKER in original and FULL_END_MARKER in original:
        prefix, tail = original.split(FULL_START_MARKER, 1)
        _, suffix = tail.split(FULL_END_MARKER, 1)
        updated = prefix.rstrip() + "\n\n" + block + suffix
    else:
        updated = original.rstrip() + "\n\n" + block + "\n"
    PROGRESS_DOC.write_text(updated, encoding="utf-8")


def markdown_table_columns(line: str) -> list[str]:
    """Split one Markdown table row without a backtracking expression."""
    if len(line) < 2 or line[0] != "|" or line[-1] != "|":
        return []

    columns: list[str] = []
    current: list[str] = []
    index = 1
    end = len(line) - 1
    while index < end:
        character = line[index]
        if character == "\\" and index + 1 < end and line[index + 1] == "|":
            current.append("|")
            index += 2
            continue
        if character == "|":
            columns.append("".join(current).strip())
            current = []
        else:
            current.append(character)
        index += 1
    columns.append("".join(current).strip())
    return columns


def is_technique_id(value: str) -> bool:
    if not value.startswith("T"):
        return False
    components = value[1:].split(".")
    return 1 <= len(components) <= 2 and all(component.isdigit() and component for component in components)


def previous_results() -> dict[str, dict[str, str]]:
    if not PROGRESS_DOC.exists():
        return {}
    results: dict[str, dict[str, str]] = {}
    for line in PROGRESS_DOC.read_text(encoding="utf-8").splitlines():
        columns = markdown_table_columns(line)
        if len(columns) != 4 or not is_technique_id(columns[0]):
            continue
        results[columns[0]] = {
            "status": columns[2],
            "evidence": columns[3],
        }
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="print every fixture and expected evidence")
    parser.add_argument("--only", action="append", default=[], metavar="ID[,ID]",
                        help="run only the selected ATT&CK row IDs")
    parser.add_argument("--failed", action="store_true",
                        help="run only rows not previously PASS, PREVENTED, or DETECTED")
    parser.add_argument("--field-evidence", action="append", default=[], metavar="ID=INCIDENT_ID",
                        help="accept a matching persisted field incident for a manual row")
    parser.add_argument("--strict", action="store_true",
                        help="require installed Strict Mode and report only durable prevention evidence")
    parser.add_argument("--hash-manifest", type=Path, metavar="PATH",
                        help="compare an external SHA-256-only manifest with the installed catalog")
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
    old_results = previous_results()
    selected = {item.strip() for group in args.only for item in group.split(",") if item.strip()}
    if args.failed:
        selected |= {
            technique["id"] for technique in techniques
            if old_results.get(technique["id"], {}).get("status") not in COMPLETED_STATUSES
        }
    if selected:
        unknown = selected - {technique["id"] for technique in techniques}
        if unknown:
            raise SystemExit("Unknown technique ID(s): " + ", ".join(sorted(unknown)))
        techniques_to_run = [technique for technique in techniques if technique["id"] in selected]
    else:
        techniques_to_run = techniques
    if args.dry_run:
        for index, technique in enumerate(techniques_to_run, 1):
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

    if args.strict:
        try:
            strict_enabled, kill_switch = strict_mode_configuration()
        except (OSError, ValueError) as error:
            raise SystemExit(f"Could not verify installed Strict Mode: {error}") from error
        if not strict_enabled or kill_switch:
            raise SystemExit(
                "--strict requires Strict Mode ON and Emergency stop blocking OFF in the installed app."
            )

    hash_result: dict[str, str] | None = None
    if args.hash_manifest:
        try:
            hash_result = replay_hash_manifest(args.hash_manifest)
        except (OSError, ValueError, sqlite3.Error) as error:
            raise SystemExit(f"Hash replay failed: {error}") from error
        print(
            f"Hash replay: {hash_result['alerted']}/{hash_result['total']} "
            f"({hash_result['percentage']}) present in the installed signature catalog."
        )

    results: dict[str, dict[str, str]] = dict(old_results)
    total = len(techniques_to_run)
    print(f"Expected recorder build: {EXPECTED_BUILD}")
    print(f"Installed Nick.app build: {app_build}")
    for bundle_id in EXPECTED_EXTENSIONS:
        print(f"Active {bundle_id} build: {extension_builds[bundle_id]}")
    print(f"Nick installed {total}-technique replay. Use declared synthetic fixtures only.")
    if args.strict:
        print("Strict Mode replay: ON; only durable quarantine, remediation, kill, or AUTH-deny evidence counts as PREVENTED.")
    corpus_only = bool(args.hash_manifest) and not (
        args.only or args.failed or args.field_evidence or args.strict
    )
    if corpus_only:
        update_full_scorecard(techniques, results, hash_result)
        print(f"Wrote the hash-level result to {PROGRESS_DOC}; no sample was stored or executed.")
        return 0
    field_evidence = dict(item.split("=", 1) for item in args.field_evidence if "=" in item)
    all_incidents = load_incident_fingerprints()
    for index, technique in enumerate(techniques_to_run, 1):
        print(f"\n[{index}/{total}] {technique['id']} — {technique['name']}")
        fixture_name = technique["fixture"]
        print(INSTRUCTIONS[fixture_name])
        if technique["id"] in field_evidence:
            incident_id = field_evidence[technique["id"]]
            matches = [(key, record) for key, record in all_incidents.items()
                       if key.startswith(incident_id + ":")]
            expected_reasons, expected_tiers = EXPECTED[technique["id"]]
            if not matches or not any(set(record["reasons"]).intersection(expected_reasons)
                                      for _, record in matches):
                raise SystemExit(f"Field incident {incident_id} does not match {technique['id']}")
            results[technique["id"]] = {
                "status": FIELD_EVIDENCE_STATUS,
                "evidence": f"persisted incident {incident_id}; verified existing field evidence",
            }
            print("Accepted matching persisted field evidence.")
            continue
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
        print(f"Fixture action: {fixture}")
        started = time.time()
        manual_completed = False
        fixture_returncode = 0
        fixture_correlation_value: str | None = None
        fixture_expected_path: str | None = None
        with tempfile.TemporaryDirectory(prefix="nick-scorecard-") as scratch:
            environment = os.environ.copy()
            environment["NICK_FIXTURE_ROOT"] = scratch
            uid = int(os.environ.get("SUDO_UID", "0"))
            gid = int(os.environ.get("SUDO_GID", "0"))
            prepare_fixture_scratch(scratch, uid, gid)
            if fixture_name == "login-item-add":
                # BTM attributes the change to System Events and does not
                # reliably preserve the fixture bundle identifier. The exact,
                # randomized app path is persisted, however, and uniquely ties
                # the incident to this recorder run.
                fixture_expected_path = os.path.join(
                    scratch, "Nick Login Item Fixture.app"
                )
            if uid > 0 and fixture_name not in ROOT_FIXTURES:
                user = pwd.getpwuid(uid).pw_name
                if fixture_name == "login-item-add":
                    command = console_user_fixture_command(fixture, scratch, user, uid)
                else:
                    command = user_fixture_command(fixture, scratch, user)
            else:
                command = [str(fixture)]
            if fixture_name == "file-deletion":
                if uid <= 0:
                    results[technique["id"]] = {
                        "status": "FAIL",
                        "evidence": "invoking user unavailable; fixture was not run as root",
                    }
                    print("No SUDO_UID was available; refusing to run this home fixture as root.")
                    continue
                results[technique["id"]] = run_file_deletion_replay(
                    fixture, scratch, user, before, started
                )
                print(
                    f"Measured: {results[technique['id']]['status']} "
                    f"({results[technique['id']]['evidence']})"
                )
                continue
            interactive = fixture_name in INTERACTIVE_FIXTURES
            completed, fixture_lineage = run_fixture_with_lineage(
                command, environment, interactive, timeout=60,
            )
            fixture_returncode = completed.returncode
            if completed.stdout:
                print(completed.stdout.rstrip())
                if fixture_name == "login-item-add":
                    marker = "NICK_FIXTURE_LOGIN_ITEM="
                    fixture_correlation_value = next(
                        (line[len(marker):].strip() for line in completed.stdout.splitlines()
                         if line.startswith(marker)),
                        None,
                    )
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
        expected_reasons, expected_tiers = EXPECTED[technique["id"]]
        required_lineage = fixture_lineage if technique["id"] in MAPPING_REVIEW_TECHNIQUES else None
        if technique["id"] == LOGIN_ITEMS_TECHNIQUE and fixture_expected_path:
            # BTM reports the daemon that commits the login item, not the
            # originating osascript process. Preserve strict correlation with
            # the fixture's exact randomized app path instead of accepting an
            # unrelated background-item event from the same time window.
            required_lineage = None
        after, matches = wait_for_matching_incidents(
            before, expected_reasons, expected_tiers,
            expected_path=fixture_expected_path,
            fixture_lineage=required_lineage,
            expected_correlation_value=(
                fixture_correlation_value if fixture_expected_path is None else None
            ),
        )
        describe_new_occurrences(before, after, required_lineage)
        prevention_after = prevention_fingerprints()
        new_ids = sorted(set(after) - set(before))
        if matches:
            latency = time.time() - started
            identifier, record = matches[0]
            rule = sorted(set(record["reasons"]).intersection(expected_reasons))[0]
            tier = sorted(set(record["tiers"]).intersection(expected_tiers))[0] if record["tiers"] else "not recorded"
            evidence = f"{identifier}; rule={rule}; tier={tier}; observed<= {latency:.2f}s"
            prevention = matching_prevention(prevention_before, prevention_after, record)
            status = measured_status(prevention, technique["id"])
            if prevention is not None:
                evidence += f"; prevention={prevention['kind']} target={prevention['target']}"
            if args.strict and status != "PREVENTED":
                status = "DETECTED"
                evidence += "; strict mode produced no durable prevention record"
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
    update_full_scorecard(techniques, results, hash_result)
    prevented_rows = sorted(
        technique["id"] for technique in techniques
        if results.get(technique["id"], {}).get("status") == "PREVENTED"
    )
    if args.strict:
        detection_only = sorted(
            technique["id"] for technique in techniques
            if results.get(technique["id"], {}).get("status") in {"PASS", "DETECTED", FIELD_EVIDENCE_STATUS}
        )
        print(f"Strict prevention proven today: {', '.join(prevented_rows) or 'none'}")
        print(f"Detected but not prevented in this run: {', '.join(detection_only) or 'none'}")
        print(f"Strict target: {len(prevented_rows)}/24 PREVENTED; required minimum is 6/24.")
    print(f"\nWrote measured rows and pending placeholders to {PROGRESS_DOC}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
