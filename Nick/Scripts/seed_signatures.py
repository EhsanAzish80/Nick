#!/usr/bin/env python3
# seed_signatures.py
# Fetches macOS malware hashes from MalwareBazaar and seeds the Nick
# signature database (SQLite at /Library/Application Support/com.ehsanazish.nick/signatures.db).
#
# Usage:
#   python3 seed_signatures.py [--db PATH] [--limit N] [--dry-run]
#
# Requirements:
#   pip install requests
#
# MARK: - Nick
# Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
# Licensed under AGPL-3.0. See LICENSE for details.

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("ERROR: 'requests' is required.  Run:  pip install requests")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

API_URL = "https://mb-api.abuse.ch/api/v1/"
DEFAULT_DB = Path("/Library/Application Support/com.ehsanazish.nick/signatures.db")
DEFAULT_LIMIT = 1000

# Map MalwareBazaar confidence strings → Nick severity strings
SEVERITY_MAP = {
    "100": "critical",
    "75":  "high",
    "50":  "medium",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fetch_signatures(limit: int) -> list[dict]:
    """Fetch macOS-tagged signatures from MalwareBazaar."""
    payload = {
        "query": "get_taginfo",
        "tag":   "macos",
        "limit": str(limit),
    }
    try:
        resp = requests.post(API_URL, data=payload, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as exc:
        sys.exit(f"ERROR: MalwareBazaar request failed: {exc}")

    body = resp.json()
    if body.get("query_status") != "ok":
        sys.exit(f"ERROR: Unexpected API status: {body.get('query_status')}")

    return body.get("data", [])


def map_entry(raw: dict) -> dict | None:
    """Convert one MalwareBazaar entry to our schema.  Returns None to skip."""
    sha256 = raw.get("sha256_hash", "").strip().lower()
    if not sha256 or len(sha256) != 64:
        return None
    name     = raw.get("signature") or raw.get("file_name") or "Unknown"
    family   = raw.get("tags", ["Unknown"])[0] if raw.get("tags") else "Unknown"
    conf_str = str(raw.get("intelligence", {}).get("detections", {}).get("undetected", "50"))
    severity = SEVERITY_MAP.get(conf_str, "medium")
    return {"hash": sha256, "name": name, "family": family, "severity": severity}


def seed_db(db_path: Path, entries: list[dict]) -> int:
    """Bulk-upsert entries into the SQLite database.  Returns number inserted."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(db_path))
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("""
        CREATE TABLE IF NOT EXISTS signatures (
            hash      TEXT PRIMARY KEY,
            name      TEXT NOT NULL,
            family    TEXT NOT NULL,
            severity  TEXT NOT NULL,
            added_at  TEXT NOT NULL
        )
    """)

    now = datetime.now(timezone.utc).isoformat()
    with con:
        con.executemany(
            """
            INSERT OR REPLACE INTO signatures (hash, name, family, severity, added_at)
            VALUES (:hash, :name, :family, :severity, :added_at)
            """,
            [{**e, "added_at": now} for e in entries],
        )
    total = con.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
    con.close()
    return total


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Nick signature database from MalwareBazaar.")
    parser.add_argument("--db",      default=str(DEFAULT_DB), help="Path to signatures.db")
    parser.add_argument("--limit",   type=int, default=DEFAULT_LIMIT, help="Max entries to fetch (default 1000)")
    parser.add_argument("--dry-run", action="store_true", help="Fetch and parse but do not write to DB")
    args = parser.parse_args()

    print(f"Fetching up to {args.limit} macOS signatures from MalwareBazaar…")
    raw_entries = fetch_signatures(args.limit)
    print(f"  → {len(raw_entries)} raw entries received.")

    mapped = [e for raw in raw_entries if (e := map_entry(raw)) is not None]
    print(f"  → {len(mapped)} valid signatures after parsing.")

    # Dump summary JSON for inspection
    summary_path = Path("seed_summary.json")
    summary_path.write_text(json.dumps(mapped[:20], indent=2))
    print(f"  → First 20 entries written to {summary_path} for review.")

    if args.dry_run:
        print("Dry-run mode — database NOT modified.")
        return

    db_path = Path(args.db)
    total = seed_db(db_path, mapped)
    print(f"  ✓ Database updated: {total} total signatures in {db_path}")


if __name__ == "__main__":
    main()
