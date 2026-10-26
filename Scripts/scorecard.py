#!/usr/bin/env python3
"""Validate Nick replay manifests and print an evidence-only scorecard."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPLAY = ROOT / "Validation" / "Replay"
ALLOWED_STATUSES = {
    "alerted",
    "prevented",
    "missed",
    "not measured",
    "measurement pending",
    "not done",
    "unsupported",
}


def load(name: str) -> dict[str, Any]:
    with (REPLAY / name).open(encoding="utf-8") as handle:
        value = json.load(handle)
    if value.get("schemaVersion") != 1:
        raise ValueError(f"{name}: unsupported schemaVersion")
    return value


def validate_manifests() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    techniques = load("attack-techniques.json")
    corpus = load("corpus-manifest.json")
    workload = load("workload-manifest.json")

    if techniques.get("attackVersion") != "20.0" or techniques.get("platform") != "macOS":
        raise ValueError("attack-techniques.json must pin ATT&CK 20.0 for macOS")
    entries = techniques.get("techniques", [])
    ids = [entry.get("id") for entry in entries]
    fixtures = [entry.get("fixture") for entry in entries]
    if len(entries) != 24 or len(set(ids)) != 24 or len(set(fixtures)) != 24:
        raise ValueError("attack-techniques.json must contain 24 unique techniques and fixtures")
    if not all(entry.get("name") and entry.get("category") for entry in entries):
        raise ValueError("every technique needs a name and category")
    mandatory = {entry["fixture"] for entry in entries if entry.get("mandatory")}
    if mandatory != {"launch-agent-add", "download-to-shell", "keychain-dump-pattern", "nick-tamper"}:
        raise ValueError("mandatory technique set changed")

    families = corpus.get("families", [])
    hashes: set[str] = set()
    for family in families:
        for field in ("family", "source", "licence", "sha256"):
            if not family.get(field):
                raise ValueError(f"corpus entry missing {field}")
        digest = family["sha256"].lower()
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("corpus SHA-256 must be 64 lowercase hexadecimal characters")
        if digest in hashes:
            raise ValueError("corpus contains a duplicate SHA-256")
        hashes.add(digest)

    workloads = workload.get("workloads", [])
    if workload.get("minimumActiveHours") != 40 or not workloads:
        raise ValueError("workload manifest must preserve the cumulative 40-hour evidence target")
    workload_ids = [entry.get("id") for entry in workloads]
    if len(workload_ids) != len(set(workload_ids)) or not all(entry.get("name") for entry in workloads):
        raise ValueError("workload IDs must be unique and named")
    return techniques, corpus, workload


def validate_results(results: dict[str, Any], technique_ids: set[str]) -> None:
    if results.get("schemaVersion") != 1:
        raise ValueError("results: unsupported schemaVersion")
    for name, measurement in results.get("measurements", {}).items():
        if measurement.get("status") not in ALLOWED_STATUSES:
            raise ValueError(f"measurement {name} has an unsupported status")
    seen: set[str] = set()
    for result in results.get("techniqueResults", []):
        identifier = result.get("id")
        if identifier not in technique_ids:
            raise ValueError(f"result references unpinned technique {identifier}")
        if identifier in seen:
            raise ValueError(f"duplicate technique result {identifier}")
        if result.get("status") not in {"alerted", "prevented", "missed"}:
            raise ValueError(f"technique {identifier} lacks a measured outcome")
        if not result.get("evidence"):
            raise ValueError(f"technique {identifier} lacks evidence")
        seen.add(identifier)


def measured_fraction(results: dict[str, Any], total: int) -> str:
    outcomes = results.get("techniqueResults", [])
    if not outcomes:
        return "not measured"
    alerted = sum(item["status"] in {"alerted", "prevented"} for item in outcomes)
    prevented = sum(item["status"] == "prevented" for item in outcomes)
    return f"{alerted}/{total} alerted; {prevented}/{total} prevented; {len(outcomes)}/{total} measured"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, default=REPLAY / "baseline-results.json")
    parser.add_argument("--check", action="store_true", help="validate inputs without printing the table")
    args = parser.parse_args()

    techniques, corpus, workload = validate_manifests()
    with args.results.open(encoding="utf-8") as handle:
        results = json.load(handle)
    technique_ids = {entry["id"] for entry in techniques["techniques"]}
    validate_results(results, technique_ids)
    if args.check:
        print("Replay manifests and scorecard evidence are valid.")
        return 0

    measurements = results["measurements"]
    rows = [
        ("Known families — hash/signature", measurements["knownFamiliesHash"]["status"]),
        ("Known families — behaviour only", measurements["knownFamiliesBehavior"]["status"]),
        ("ATT&CK for macOS v20.0 (24 pinned)", measured_fraction(results, len(technique_ids))),
        ("Extension stopped, app alive", measurements["extensionStopped"]["status"]),
        ("Extension and app both gone", measurements["extensionAndAppGone"]["status"]),
        (f"False positives ({workload['minimumActiveHours']} active hours)", measurements["falsePositives"]["status"]),
        ("Endpoint Security health", measurements["endpointSecurityHealth"]["status"]),
        ("Independent security review", measurements["independentReview"]["status"]),
    ]
    print(f"Nick {results['release']} build {results['build']} baseline")
    print("| Metric | Result |")
    print("|---|---|")
    for metric, result in rows:
        print(f"| {metric} | {result} |")
    print(f"\nCorpus entries: {len(corpus.get('families', []))} (SHA-256 deduplicated)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
