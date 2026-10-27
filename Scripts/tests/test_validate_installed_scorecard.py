import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "Scripts" / "validate-installed-scorecard.py"
SPEC = importlib.util.spec_from_file_location("installed_scorecard", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class PrivilegedStoreDecodeTests(unittest.TestCase):
    def test_real_privileged_store_wrapper_decodes_occurrence(self):
        fixture = Path(__file__).parent / "fixtures" / "privileged-incidents.json"
        snapshot = MODULE.decode_privileged_store(fixture.read_bytes())
        self.assertEqual(snapshot["incidents"][0]["occurrenceCount"], 3)
        self.assertEqual(snapshot["incidents"][0]["id"], "11111111-1111-1111-1111-111111111111")

    def test_plain_snapshot_is_rejected(self):
        with self.assertRaises(ValueError):
            MODULE.decode_privileged_store(b'{"incidents":[]}')


if __name__ == "__main__":
    unittest.main()
