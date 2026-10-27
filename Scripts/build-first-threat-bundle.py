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
import os
from pathlib import Path
import stat
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
HASHES = ROOT / "NickExtension" / "known-threat-hashes.json"
RULES = ROOT / "Validation" / "ThreatIntelligence" / "first-bundle-rules.json"
PRODUCTION_PUBLIC_KEY = base64.b64decode("XIYgv92Pzh9CcUrooo2psW5wly507Oxv6oN0a2dbb/0=", validate=True)
OPENSSL_CANDIDATES = (
    Path("/opt/homebrew/opt/openssl@3/bin/openssl"),
    Path("/usr/local/opt/openssl@3/bin/openssl"),
    Path("/opt/homebrew/bin/openssl"),
    Path("/usr/local/bin/openssl"),
)


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


def invoking_uid() -> int:
    sudo_uid = os.environ.get("SUDO_UID")
    return int(sudo_uid) if sudo_uid is not None else os.getuid()


def validate_private_key(path: Path) -> Path:
    absolute = path.expanduser().resolve(strict=True)
    metadata = absolute.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.expanduser().is_symlink():
        raise SystemExit("private key must be a regular file and not a symlink")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise SystemExit("private key mode must be 0600")
    if metadata.st_uid != invoking_uid():
        raise SystemExit("private key must be owned by the invoking user")
    return absolute


def resolve_output(path: Path, force: bool) -> Path:
    expanded = path.expanduser()
    if expanded.suffix.lower() != ".json":
        raise SystemExit("output must end in .json")
    parent = expanded.parent.resolve(strict=True)
    absolute = (parent / expanded.name).resolve(strict=False)
    if absolute.exists() and not force:
        raise SystemExit("output exists; pass --force to replace it")
    return absolute


def resolve_openssl(path: Path | None) -> Path:
    candidates = (path,) if path is not None else OPENSSL_CANDIDATES
    for candidate in candidates:
        if candidate is None:
            continue
        try:
            absolute = candidate.expanduser().resolve(strict=True)
            metadata = absolute.stat()
        except (FileNotFoundError, OSError):
            continue
        if absolute.is_absolute() and stat.S_ISREG(metadata.st_mode) and os.access(absolute, os.X_OK):
            version = subprocess.run(
                [str(absolute), "version"], check=True, capture_output=True, text=True
            ).stdout
            if version.startswith("OpenSSL 3."):
                return absolute
    raise SystemExit("OpenSSL 3 is required; pass its absolute path with --openssl")


def atomic_write(path: Path, data: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--version", required=True, type=int)
    parser.add_argument("--lifetime-days", type=int, default=90)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--openssl", type=Path, help=argparse.SUPPRESS)
    parser.add_argument(
        "--verification-public-key", type=Path,
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()
    private_key = validate_private_key(args.private_key)
    output = resolve_output(args.output, args.force)
    openssl = resolve_openssl(args.openssl)
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
        if args.verification_public_key:
            public_key = args.verification_public_key.expanduser().resolve(strict=True)
            public_path.write_bytes(public_key.read_bytes())
        else:
            public_path.write_bytes(production_public_key_pem())
        subprocess.run([
            str(openssl), "pkeyutl", "-sign", "-rawin",
            "-inkey", str(private_key), "-in", str(message_path),
            "-out", str(signature_path)
        ], check=True)
        subprocess.run([
            str(openssl), "pkeyutl", "-verify", "-rawin", "-pubin",
            "-inkey", str(public_path), "-in", str(message_path),
            "-sigfile", str(signature_path)
        ], check=True)
        bundle = {
            "payloadData": base64.b64encode(message).decode(),
            # Keep the decoded object for one release so older tooling can
            # inspect the envelope; clients verify and decode payloadData.
            "payload": payload,
            "signature": base64.b64encode(signature_path.read_bytes()).decode(),
        }
        atomic_write(output, canonical_json(bundle) + b"\n")
        print(f"Built and key-verified bundle: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
