#!/usr/bin/env python3

import ast
import base64
import re
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
