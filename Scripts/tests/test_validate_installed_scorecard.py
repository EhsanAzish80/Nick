import importlib.util
import os
from pathlib import Path
import subprocess
import sqlite3
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "Scripts" / "validate-installed-scorecard.py"
SPEC = importlib.util.spec_from_file_location("installed_scorecard", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class PrivilegedStoreDecodeTests(unittest.TestCase):
    def test_plain_snapshot_is_rejected(self):
        with self.assertRaises(ValueError):
            MODULE.decode_privileged_store(b'{"incidents":[]}')

    def test_nonzero_exit_is_not_prevention_without_durable_record(self):
        self.assertEqual(MODULE.measured_status(None), "PASS")
        self.assertEqual(
            MODULE.measured_status({"kind": "quarantine", "target": "/tmp/eicar"}),
            "PREVENTED",
        )

    def test_quarantine_database_is_authoritative_prevention_evidence(self):
        with tempfile.TemporaryDirectory(prefix="nick-quarantine-test-") as directory:
            database_path = Path(directory) / "quarantine.db"
            with sqlite3.connect(database_path) as database:
                database.execute(
                    "CREATE TABLE quarantine (id TEXT, original_path TEXT, "
                    "quarantined_path TEXT, threat_name TEXT, quarantined_at TEXT)"
                )
                database.execute(
                    "INSERT INTO quarantine VALUES (?, ?, ?, ?, ?)",
                    ("record-1", "/tmp/eicar.com", "/quarantine/eicar.com", "EICAR", "now"),
                )
            with mock.patch.object(MODULE, "QUARANTINE_DB", database_path), \
                 mock.patch.object(MODULE, "THREAT_JOURNALS", ()):
                records = MODULE.prevention_fingerprints()
            self.assertEqual(records["quarantine:record-1"]["target"], "/tmp/eicar.com")


class FixtureInvocationTests(unittest.TestCase):
    def test_sudo_uid_fixture_receives_owned_scratch_and_explicit_root(self):
        fixture = ROOT / "Scripts" / "fixtures" / "permission-modification.sh"
        with tempfile.TemporaryDirectory(prefix="nick-scorecard-test-") as scratch:
            with mock.patch.object(MODULE.os, "chown") as chown:
                MODULE.prepare_fixture_scratch(scratch, 501, 20)
            chown.assert_called_once_with(scratch, 501, 20)
            self.assertEqual(os.stat(scratch).st_mode & 0o777, 0o700)

            command = MODULE.user_fixture_command(fixture, scratch, "fixture-user")
            self.assertEqual(command, [
                "/usr/bin/sudo", "-H", "-u", "fixture-user", "--", "/usr/bin/env",
                f"NICK_FIXTURE_ROOT={scratch}", str(fixture),
            ])

            # Exercise the actual fixture with the exact env segment passed
            # after sudo. This catches both a missing env assignment and an
            # unusable root-created scratch directory without requiring CI sudo.
            env_index = command.index("/usr/bin/env")
            completed = subprocess.run(
                command[env_index:], check=False, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout)


if __name__ == "__main__":
    unittest.main()
