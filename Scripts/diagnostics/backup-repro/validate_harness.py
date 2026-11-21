#!/usr/bin/env python3
"""Pure harness checks and current-process kernel ABI smoke check; never mounts/loads Nick."""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('backup_repro', HERE / 'repro.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
# Generate no pycache from this validator; callers use python -B.
assert m.parser().parse_args([]).action == 'plan'
assert not m.parser().parse_args(['run']).execute
assert m.PROFILES['large']['entries'] == 1000000
assert m.PROFILES['sustained']['entries'] * m.PROFILES['sustained']['documentBytes'] == 5242880000
assert m.PROFILES['sustained']['entries'] + m.PROFILES['sustained']['scripts'] < 50000
paths = [m.fixture_relative(i, 12) for i in [0, 499, 500, 999999]]
assert len(set(paths)) == len(paths)
assert all(not p.is_absolute() and '..' not in p.parts for p in paths)
now = time.time()
h = {'processID': 123, 'version': '5111', 'updatedAt': now}
r = {'health': h, 'time': now, 'phys_footprint': 50 * 1024**2}
assert m.gate(r, 123, '5111', m.GIB, 60*m.GIB, now) is None
assert m.gate(r, 124, '5111', m.GIB, 60*m.GIB, now)
assert m.gate(r, 123, '5112', m.GIB, 60*m.GIB, now)
assert m.gate(r, 123, '5111', 1, 60*m.GIB, now)
assert m.gate(r, 123, '5111', m.GIB, 49*m.GIB, now)
assert m.gate(r, 123, '5111', m.GIB, 60*m.GIB, now+6)
assert m.swap_used_bytes('total = 1024.00M used = 12.50M free = 10M') == 13107200
assert m.available_bytes('Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free: 100.\nPages inactive: 200.\nPages speculative: 50.\n') == 350*16384
with tempfile.TemporaryDirectory(prefix='NickReproHarnessValidation-') as tmp:
    exe = Path(tmp) / 'layout'
    subprocess.run(['xcrun', 'clang', str(HERE/'rusage-layout.c'), '-o', str(exe)], check=True)
    layout = json.loads(subprocess.check_output([str(exe)]))
    assert layout == {'size': ctypes.sizeof(m.Usage),
        'footprintOffset': m.Usage.phys_footprint.offset,
        'lifetimePeakOffset': m.Usage.lifetime_max_phys_footprint.offset,
        'intervalPeakOffset': m.Usage.interval_max_phys_footprint.offset}, layout
    # Reproduce the observed parser failure safely: valid plist stdout plus a
    # diagnostic on stderr must stay separate. No image tool or workload.
    import plistlib
    import sys
    args = m.parser().parse_args(['--session', tmp])
    experiment = m.Experiment(args)
    stdout = experiment.command([sys.executable, '-c',
        'import plistlib,sys; sys.stdout.buffer.write(plistlib.dumps({"ok":True})); sys.stderr.write("diagnostic after XML\\n")'], safety=False)
    assert plistlib.loads(stdout) == {'ok': True}
    recorded = [json.loads(line) for line in (Path(tmp)/'events.jsonl').read_text().splitlines()]
    assert 'diagnostic after XML' in recorded[-1]['stderr']
    lib = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    lib.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    u = m.Usage()
    assert lib.proc_pid_rusage(os.getpid(), 4, ctypes.byref(u)) == 0
    assert u.phys_footprint > 0 and u.lifetime_max_phys_footprint >= u.phys_footprint
print(json.dumps({'result': 'PASS', 'layout': layout,
    'checks': ['default dry plan', 'fixture paths', 'PID/build/stale/memory/disk gates',
               'swap/memory parser', 'SDK ABI match', 'separate plist stdout/stderr', 'current-process passive rusage'],
    'notRun': ['image creation', 'mount', 'Nick load', 'SMB', 'allocation logging']}, indent=2))
