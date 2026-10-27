#!/usr/bin/env python3
"""Build, schema-check, sign and production-key-verify Nick's first bundle.

The Ed25519 private key is supplied by path at run time and is never copied
into the repository or output bundle.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
HASHES = ROOT / "NickExtension" / "known-threat-hashes.json"
RULES = ROOT / "Validation" / "ThreatIntelligence" / "first-bundle-rules.json"
PRODUCTION_PUBLIC_KEY = base64.b64decode("XIYgv92Pzh9CcUrooo2psW5wly507Oxv6oN0a2dbb/0=", validate=True)


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def validate_payload(payload: dict) -> None:
    if payload.get("schemaVersion") != 1 or not isinstance(payload.get("version"), int):
        raise ValueError("unsupported schema or invalid version")
    if payload["version"] <= 0 or payload["expiresAt"] <= payload["issuedAt"]:
        raise ValueError("invalid version or lifetime")
    if payload["expiresAt"] - payload["issuedAt"] > 180 * 24 * 60 * 60 * 1000:
        raise ValueError("bundle lifetime exceeds 180 days")
    hashes = payload.get("hashes", [])
    if not hashes or len({entry["sha256"] for entry in hashes}) != len(hashes):
        raise ValueError("hash catalog is empty or contains duplicates")
    for entry in hashes:
        digest = entry["sha256"].lower()
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("malformed SHA-256 entry")
    rules = payload.get("rules", [])
    if not rules or any(rule["confidence"] != "high" or not rule["blockable"] for rule in rules):
        raise ValueError("first bundle rules must be explicitly high-confidence and blockable")


def production_public_key_pem() -> bytes:
    # RFC 8410 SubjectPublicKeyInfo prefix for a raw 32-byte Ed25519 key.
    der = bytes.fromhex("302a300506032b6570032100") + PRODUCTION_PUBLIC_KEY
    encoded = base64.b64encode(der).decode()
    return ("-----BEGIN PUBLIC KEY-----\n" + encoded + "\n-----END PUBLIC KEY-----\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--version", required=True, type=int)
    parser.add_argument("--lifetime-days", type=int, default=90)
    args = parser.parse_args()
    if not args.private_key.is_file():
        raise SystemExit("private key path does not exist")
    if not 1 <= args.lifetime_days <= 180:
        raise SystemExit("lifetime must be between 1 and 180 days")

    catalog = json.loads(HASHES.read_text(encoding="utf-8"))
    rule_config = json.loads(RULES.read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc)
    payload = {
        "schemaVersion": 1,
        "version": args.version,
        "issuedAt": int(now.timestamp() * 1000),
        "expiresAt": int((now + timedelta(days=args.lifetime_days)).timestamp() * 1000),
        "source": "3Nsofts production threat intelligence",
        "hashes": [
            {"sha256": entry["hash"].lower(), "name": entry["name"],
             "family": entry["family"], "severity": entry["severity"].lower()}
            for entry in catalog["entries"]
        ],
        "domains": [],
        "ipAddresses": [],
        "rules": rule_config["rules"],
    }
    validate_payload(payload)
    message = canonical_json(payload)

    with tempfile.TemporaryDirectory(prefix="nick-bundle-") as directory:
        temporary = Path(directory)
        message_path = temporary / "payload.json"
        signature_path = temporary / "signature.bin"
        public_path = temporary / "production-public.pem"
        message_path.write_bytes(message)
        public_path.write_bytes(production_public_key_pem())
        subprocess.run([
            "/usr/bin/openssl", "pkeyutl", "-sign", "-rawin",
            "-inkey", str(args.private_key), "-in", str(message_path),
            "-out", str(signature_path)
        ], check=True)
        subprocess.run([
            "/usr/bin/openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
            "-inkey", str(public_path), "-in", str(message_path),
            "-sigfile", str(signature_path)
        ], check=True)
        bundle = {
            "payload": payload,
            "signature": base64.b64encode(signature_path.read_bytes()).decode(),
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical_json(bundle) + b"\n")
        print(f"Built and production-key verified bundle: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
