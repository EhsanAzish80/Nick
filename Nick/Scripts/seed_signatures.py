# MARK: - Nick
# Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
# Licensed under AGPL-3.0. See LICENSE for details.

#!/usr/bin/env python3
# seed_signatures.py
# Fetches macOS malware hashes from MalwareBazaar and seeds the Nick
# signature database (SQLite at /Library/Application Support/com.ehsanazish.nick/signatures.db).
#
# Usage:
#   python3 seed_signatures.py [--db-name NAME.db] [--limit N] [--dry-run]
#
# Requirements:
#   pip install requests
#
# MARK: - Nick
# Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
# Licensed under AGPL-3.0. See LICENSE for details.

import argparse
import json
import re
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
    "75": "high",
    "50": "medium",
}

# ---------------------------------------------------------------------------
# Path security helpers
# ---------------------------------------------------------------------------

def _allowed_db_dir() -> Path:
    """App-owned directory where the signatures DB must live."""
    return DEFAULT_DB.parent.resolve()


def _sanitize_db_name(name: str) -> str:
    """
    Allow only a simple SQLite filename (no path separators, traversal, or URI).
    Examples allowed: signatures.db, my-cache_01.db
    """
    base = Path(name).name  # strips any provided directories
    if not re.fullmatch(r"[A-Za-z0-9._-]+\.db", base):
        raise ValueError("Invalid --db-name. Use a simple filename ending in .db (e.g. signatures.db).")
    return base


def _resolve_and_validate_db_path(db_name: str) -> Path:
    """
    Build and validate DB path under the app-owned directory.
    Prevents filesystem escape and CLI-driven arbitrary DB targets.
    """
    allowed_base = _allowed_db_dir()
    safe_name = _sanitize_db_name(db_name)

    candidate = (allowed_base / safe_name).resolve()

    try:
        candidate.relative_to(allowed_base)
    except ValueError as exc:
        raise ValueError(f"Database path escapes allowed directory: {candidate}") from exc

    return candidate


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fetch_signatures(limit: int) -> list[dict]:
    """Fetch macOS-tagged signatures from MalwareBazaar."""
    payload = {
        "query": "get_taginfo",
        "tag": "macos",
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
    """Convert one MalwareBazaar entry to our schema. Returns None to skip."""
    sha256 = raw.get("sha256_hash", "").strip().lower()
    if not sha256 or len(sha256) != 64:
        return None
    name = raw.get("signature") or raw.get("file_name") or "Unknown"
    family = raw.get("tags", ["Unknown"])[0] if raw.get("tags") else "Unknown"
    conf_str = str(raw.get("intelligence", {}).get("detections", {}).get("undetected", "50"))
    severity = SEVERITY_MAP.get(conf_str, "medium")
    return {"hash": sha256, "name": name, "family": family, "severity": severity}


def seed_db(db_path: Path, entries: list[dict]) -> int:
    """Bulk-upsert entries into the SQLite database. Returns number inserted."""
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
    parser.add_argument(
        "--db-name",
        default=DEFAULT_DB.name,
        help=f"SQLite filename only (stored under {_allowed_db_dir()})",
    )
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Max entries to fetch (default 1000)")
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

    try:
        db_path = _resolve_and_validate_db_path(args.db_name)
    except ValueError as exc:
        sys.exit(f"ERROR: {exc}")

    total = seed_db(db_path, mapped)
    print(f"  ✓ Database updated: {total} total signatures in {db_path}")


if __name__ == "__main__":
    main()
