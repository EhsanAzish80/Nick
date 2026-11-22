"""Permission validation tests never need root or create system directories."""
import os
from pathlib import Path
import tempfile
import unittest
from private_paths import validate_directory

class PrivateEvidencePathsTests(unittest.TestCase):
    def test_private_directory_accepts_only_expected_owner(self):
        with tempfile.TemporaryDirectory() as value:
            path = Path(value)
            self.assertEqual(validate_directory(path, os.getuid()), path)
            with self.assertRaises(RuntimeError):
                validate_directory(path, os.getuid() + 1)

    def test_symlink_and_shared_write_are_rejected(self):
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            target = root / 'target'
            target.mkdir(mode=0o700)
            link = root / 'link'
            link.symlink_to(target)
            with self.assertRaises(RuntimeError):
                validate_directory(link, os.getuid())
            target.chmod(0o770)
            with self.assertRaises(RuntimeError):
                validate_directory(target, os.getuid())

if __name__ == '__main__':
    unittest.main()
