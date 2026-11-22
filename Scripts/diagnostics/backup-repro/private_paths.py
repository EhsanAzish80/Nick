"""Root-managed evidence paths; status is group-readable, never world-readable."""
import os
from pathlib import Path
import pwd
import stat
import tempfile

EVIDENCE_ROOT = Path('/Library/Logs/NickBackupRepro')

def validate_directory(path, owner=0):
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != owner or metadata.st_mode & 0o027:
        raise RuntimeError('Evidence directory must have the expected owner, no group write, and no world access')
    return path

def ensure_directory(path):
    path.mkdir(mode=0o750, exist_ok=True)
    return validate_directory(path)

def prepare_root():
    if os.geteuid() != 0:
        raise RuntimeError('Only root may initialize diagnostic evidence directories')
    root = ensure_directory(EVIDENCE_ROOT)
    uid = int(os.environ.get('SUDO_UID', '0'))
    group = pwd.getpwuid(uid).pw_gid
    os.chown(root, 0, group)
    return root, group

def new_status_directory():
    root, group = prepare_root()
    parent = ensure_directory(root / 'status')
    os.chown(parent, 0, group)
    directory = Path(tempfile.mkdtemp(prefix='NickBackupRepro-status-', dir=str(parent)))
    os.chown(directory, 0, group)
    directory.chmod(0o750)
    return directory, group
