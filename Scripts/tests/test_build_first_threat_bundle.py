#!/usr/bin/env python3

import ast
import base64
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
PUBLISHER = ROOT / "Scripts" / "build-first-threat-bundle.py"
SWIFT_VALIDATOR = ROOT / "Shared" / "SignedThreatIntelligenceBundle.swift"


def production_key_from_publisher() -> bytes:
    source = PUBLISHER.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "PRODUCTION_PUBLIC_KEY"
                   for target in node.targets):
            continue
        call = node.value
        if (isinstance(call, ast.Call) and call.args
                and isinstance(call.args[0], ast.Constant)
                and isinstance(call.args[0].value, str)):
            return base64.b64decode(call.args[0].value, validate=True)
    raise AssertionError("publisher production key constant was not found")


def production_key_from_swift() -> bytes:
    source = SWIFT_VALIDATOR.read_text(encoding="utf-8")
    match = re.search(
        r"productionPublicKey\s*=\s*Data\(\s*base64Encoded:\s*\"([^\"]+)\"",
        source,
        re.MULTILINE,
    )
    if match is None:
        raise AssertionError("Swift production key constant was not found")
    return base64.b64decode(match.group(1), validate=True)


class ProductionKeyParityTests(unittest.TestCase):
    def test_python_publisher_and_swift_validator_pin_identical_key_bytes(self):
        publisher_key = production_key_from_publisher()
        swift_key = production_key_from_swift()

        self.assertEqual(len(publisher_key), 32)
        self.assertEqual(publisher_key, swift_key)

    def test_signing_staging_paths_are_generated_internally(self):
        source = PUBLISHER.read_text(encoding="utf-8")

        self.assertIn("tempfile.NamedTemporaryFile", source)
        self.assertNotIn('temporary / "payload.json"', source)
        self.assertNotIn("message_path.write_bytes", source)
        self.assertNotIn("public_path.write_bytes", source)


class CanaryBundleTests(unittest.TestCase):
    def build_payload(self, include_canaries: bool) -> dict:
        openssl = next(
            (path for path in (
                Path("/opt/homebrew/opt/openssl@3/bin/openssl"),
                Path("/usr/local/opt/openssl@3/bin/openssl"),
                Path("/opt/homebrew/bin/openssl"),
                Path("/usr/local/bin/openssl"),
            ) if path.is_file()),
            None,
        )
        if openssl is None:
            self.skipTest("OpenSSL 3 is not installed")
        with tempfile.TemporaryDirectory(prefix="nick-canary-test-") as directory:
            root = Path(directory)
            private_key = root / "test-key.pem"
            public_key = root / "test-public.pem"
            output = root / "bundle.json"
            subprocess.run(
                [str(openssl), "genpkey", "-algorithm", "Ed25519", "-out", str(private_key)],
                check=True,
            )
            private_key.chmod(0o600)
            with public_key.open("wb") as stream:
                subprocess.run(
                    [str(openssl), "pkey", "-in", str(private_key), "-pubout"],
                    check=True,
                    stdout=stream,
                )
            command = [
                os.fspath(PUBLISHER),
                "--private-key", os.fspath(private_key),
                "--output", os.fspath(output),
                "--version", "2",
                "--openssl", os.fspath(openssl),
                "--verification-public-key", os.fspath(public_key),
            ]
            if include_canaries:
                command.append("--include-canaries")
            environment = os.environ.copy()
            environment["NICK_BUNDLE_TEST"] = "1"
            environment["PYTHONPYCACHEPREFIX"] = os.fspath(root / "pycache")
            subprocess.run(command, check=True, env=environment, capture_output=True)
            envelope = json.loads(output.read_text(encoding="utf-8"))
            return json.loads(base64.b64decode(envelope["payloadData"]))

    def test_default_bundle_does_not_contain_canaries(self):
        payload = self.build_payload(include_canaries=False)
        self.assertNotIn("domainIndicators", payload)
        self.assertFalse(any(entry.get("identifier", "").startswith("NICK_CANARY_")
                             for entry in payload["hashes"]))

    def test_include_canaries_adds_fixed_file_and_web_indicators(self):
        payload = self.build_payload(include_canaries=True)
        marker = (ROOT / "Scripts" / "fixtures" / "canary_marker.txt").read_bytes()
        self.assertEqual(len(marker), 64)
        self.assertTrue(marker.isascii())
        file_entry = next(entry for entry in payload["hashes"]
                          if entry.get("identifier") == "NICK_CANARY_FILE")
        self.assertEqual(file_entry["sha256"], hashlib.sha256(marker).hexdigest())
        self.assertEqual(file_entry["name"], "Nick test indicator")
        self.assertEqual(file_entry["family"], "test")
        self.assertEqual(file_entry["severity"], "info")
        self.assertEqual(payload["domainIndicators"], [{
            "domain": "nick-canary.3nsofts.com",
            "identifier": "NICK_CANARY_WEB",
        }])


if __name__ == "__main__":
    unittest.main()
