#!/usr/bin/env python3
"""Synthetic reads/mmaps and bounded modified-file churn. Never execute fixtures."""
import argparse
import json
import mmap
import os
from pathlib import Path
import shutil
import signal
import tempfile
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--read-root', required=True)
p.add_argument('--scratch-parent', required=True)
p.add_argument('--seconds', type=int, default=60)
p.add_argument('--opens-per-second', type=int, default=1000)
a = p.parse_args()
if not 1 <= a.seconds <= 1800 or not 1 <= a.opens_per_second <= 5000:
    raise SystemExit('Worker bounds exceeded')
root = Path(a.read_root).resolve(strict=True)
if not str(root).startswith('/Volumes/NickRepro-'):
    raise SystemExit('Only harness-mounted synthetic volumes can be read')
parent = Path(a.scratch_parent).resolve(strict=True)
stop = False

def request_stop(signum, frame):
    global stop
    stop = True

for sig in [signal.SIGINT, signal.SIGTERM, signal.SIGHUP]:
    signal.signal(sig, request_stop)
# Discovery is itself load, explicitly included in the phase and time cap.
started = time.monotonic()
paths = []
for path in root.rglob('*'):
    if stop or time.monotonic()-started >= a.seconds:
        break
    if path.is_file() and not path.is_symlink():
        paths.append(path)
        if len(paths) == 2000:
            break
if not paths:
    raise SystemExit('No fixture files discovered')
scratch = Path(tempfile.mkdtemp(prefix='synthetic-chunks-', dir=parent))
count = 0
last_report = started
last_write = started-10
try:
    while not stop and time.monotonic()-started < a.seconds:
        if shutil.disk_usage(parent).free < 50*1024**3:
            raise RuntimeError('Worker free-disk ceiling')
        tick = time.monotonic()
        for _ in range(max(1, a.opens_per_second//10)):
            if stop or time.monotonic()-started >= a.seconds:
                break
            path = paths[count % len(paths)]
            with path.open('rb') as f:
                f.read(4096)
                if os.fstat(f.fileno()).st_size:
                    with mmap.mmap(f.fileno(), min(4096, os.fstat(f.fileno()).st_size), access=mmap.ACCESS_READ) as mapping:
                        _ = mapping[0]
            count += 1
        if time.monotonic()-last_write >= 10:
            # Rewrite a single 64 MiB generated chunk using a 1 MiB buffer.
            with (scratch/'synthetic-backup.chunk').open('wb') as f:
                block = b'Nick harmless synthetic backup chunk.\n'.ljust(1024**2, b'.')
                for _ in range(64):
                    if stop:
                        break
                    f.write(block)
            last_write = time.monotonic()
        if time.monotonic()-last_report >= 1:
            print(json.dumps({'elapsed': time.monotonic()-started, 'opens': count,
                  'achievedOpensPerSecond': count/max(.001,time.monotonic()-started)}), flush=True)
            last_report = time.monotonic()
        time.sleep(max(0,.1-(time.monotonic()-tick)))
finally:
    shutil.rmtree(scratch)
print(json.dumps({'completedOpens': count, 'seconds': time.monotonic()-started,
      'scratchRemoved': not scratch.exists(), 'requestedRate': a.opens_per_second}), flush=True)
