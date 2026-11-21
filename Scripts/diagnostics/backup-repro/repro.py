#!/usr/bin/env python3
"""Private, bounded external-volume reproduction. Default action is plan only."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid

HEALTH = Path('/Library/Application Support/com.ehsanazish.nick/extension_health.json')
SETTINGS = Path('/Library/Application Support/com.ehsanazish.nick/state/settings.json')
GIB = 1024 ** 3
PROFILES = {
    'small': {'entries': 10000, 'scripts': 2000, 'depth': 6, 'imageGiB': 4},
    'medium': {'entries': 100000, 'scripts': 10000, 'depth': 10, 'imageGiB': 8},
    'sustained': {'entries': 40000, 'scripts': 2000, 'depth': 10, 'imageGiB': 12, 'documentBytes': 128 * 1024},
    'large': {'entries': 1000000, 'scripts': 30000, 'depth': 12, 'imageGiB': 16},
}
# Exact RUSAGE_INFO_V4 layout from the installed macOS SDK sys/resource.h.
FIELDS = '''user_time system_time pkg_idle_wkups interrupt_wkups pageins wired_size
resident_size phys_footprint proc_start_abstime proc_exit_abstime child_user_time
child_system_time child_pkg_idle_wkups child_interrupt_wkups child_pageins
child_elapsed_abstime diskio_bytesread diskio_byteswritten cpu_time_qos_default
cpu_time_qos_maintenance cpu_time_qos_background cpu_time_qos_utility cpu_time_qos_legacy
cpu_time_qos_user_initiated cpu_time_qos_user_interactive billed_system_time
serviced_system_time logical_writes lifetime_max_phys_footprint instructions cycles
billed_energy serviced_energy interval_max_phys_footprint runnable_time'''.split()

class Usage(ctypes.Structure):
    _fields_ = [('uuid', ctypes.c_uint8 * 16)] + [(n, ctypes.c_uint64) for n in FIELDS]

class Timebase(ctypes.Structure):
    _fields_ = [('numer', ctypes.c_uint32), ('denom', ctypes.c_uint32)]


def swap_used_bytes(text):
    match = re.search(r'used = ([0-9.]+)([KMG])', text)
    if not match:
        raise RuntimeError('Cannot parse swap usage')
    return int(float(match[1]) * {'K': 1024, 'M': 1024**2, 'G': GIB}[match[2]])


def available_bytes(text):
    size = re.search(r'page size of (\d+) bytes', text)
    values = dict(re.findall(r'^(Pages [^:]+):\s+(\d+)\.', text, re.M))
    if not size or 'Pages free' not in values:
        raise RuntimeError('Cannot parse passive memory counters')
    return int(size[1]) * sum(int(values.get(k, 0)) for k in
                             ['Pages free', 'Pages inactive', 'Pages speculative'])


def emit(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n')


def read_health():
    return json.loads(HEALTH.read_text())


def fixture_relative(n, depth, script=False):
    # Deep paths without using real accounts or backup contents.
    parts = ['backup-tree', 'SyntheticUser'] + ['level-%02d' % i for i in range(depth)]
    parts += ['batch-%05d' % (n // 500)]
    return Path(*parts) / ('harmless-%08d.sh' % n if script else 'document-%08d.txt' % n)


def gate(sample, pid, build, footprint_limit, free_bytes, now):
    if sample['health'].get('processID') != pid or sample['health'].get('version') != build:
        return 'Extension identity/build changed'
    if sample['time'] - sample['health'].get('updatedAt', 0) > 90:
        return 'Extension health stale'
    if now - sample['time'] > 5:
        return 'Passive sampling stale'
    if sample['phys_footprint'] >= footprint_limit:
        return 'Extension footprint ceiling reached'
    if free_bytes < 50 * GIB:
        return 'Less than 50 GiB free on evidence volume'
    return None


class Experiment:
    def __init__(self, args):
        self.a = args
        self.session = Path(args.session).expanduser().resolve()
        self.stop = threading.Event()
        self.reason = None
        self.latest = None
        self.thread = None
        self.mounts = []
        self.started = time.monotonic()
        self.evidence_lock = threading.Lock()

    def event(self, kind, **data):
        with self.evidence_lock:
            with (self.session / 'events.jsonl').open('a') as f:
                f.write(json.dumps({'time': time.time(), 'kind': kind, **data}) + '\n')

    def command(self, argv, timeout=60, safety=True):
        self.event('command-start', argv=argv)
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            p = subprocess.Popen(argv, stdout=output, stderr=errors)
            started = time.monotonic()
            try:
                while p.poll() is None:
                    if safety:
                        self.check()
                    if time.monotonic() - started > timeout:
                        raise RuntimeError('Command timeout: ' + argv[0])
                    time.sleep(.1)
            except BaseException:
                p.terminate()
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait()
                raise
            output.seek(0)
            data = output.read()
            errors.seek(0)
            error_data = errors.read()
        self.event('command-end', argv=argv, returncode=p.returncode,
                   output=data.decode(errors='replace')[-12000:],
                   stderr=error_data.decode(errors='replace')[-12000:])
        if p.returncode:
            raise RuntimeError('Command failed: ' + argv[0])
        return data

    def check(self):
        if self.stop.is_set():
            raise RuntimeError(self.reason or 'Stop requested')
        if (self.session / 'STOP').exists():
            raise RuntimeError('Operator STOP marker')
        if time.monotonic() - self.started > self.a.total_minutes * 60:
            raise RuntimeError('Total experiment time limit')
        if self.latest:
            problem = gate(self.latest, self.pid, self.a.expected_build,
                           self.a.max_footprint_mib * 1024 ** 2,
                           shutil.disk_usage(self.session).free, time.time())
            if problem:
                raise RuntimeError(problem)

    def start(self):
        if os.geteuid() != 0:
            raise RuntimeError('Use sudo only for an explicit prepare/run action')
        self.session.mkdir(mode=0o700, parents=True, exist_ok=False)
        os.chmod(self.session, 0o700)
        self.h = read_health()
        self.pid = self.h['processID']
        if self.h.get('version') != self.a.expected_build or not self.h.get('active'):
            raise RuntimeError('Wrong or inactive extension build')
        if int(self.a.expected_build) >= 5112 and 'mountStartupDiagnostics' not in self.h:
            raise RuntimeError('5112 mount startup diagnostics missing')
        if 'scanWorkDiagnostics' not in self.h or 'pendingAuthDiagnostics' not in self.h:
            raise RuntimeError('Required diagnostics missing')
        self.settings_hash = hashlib.sha256(SETTINGS.read_bytes()).hexdigest()
        with Path('/Applications/Nick.app/Contents/Info.plist').open('rb') as f:
            if str(plistlib.load(f)['CFBundleVersion']) != self.a.expected_build:
                raise RuntimeError('App build mismatch')
        extensions = subprocess.check_output(['/usr/bin/systemextensionsctl', 'list'], text=True, timeout=10)
        for ident in ['com.ehsanazish.nick.NickExtension', 'com.ehsanazish.nick.NickNetFilter']:
            lines = [s for s in extensions.splitlines() if ident in s and '[activated enabled]' in s]
            if len(lines) != 1 or '/' + self.a.expected_build + ')' not in lines[0]:
                raise RuntimeError('Active extension build mismatch: ' + ident)
        (self.session / 'extensions.txt').write_text(extensions)
        emit(self.session / 'before-health.json', self.h)
        emit(self.session / 'plan.json', vars(self.a))
        self.status_root = Path(tempfile.mkdtemp(prefix='NickBackupRepro-status-', dir='/private/tmp'))
        os.chmod(self.status_root, 0o755)
        print('Read-only status:', self.status_root / 'status.json', flush=True)
        self.initial_reports = self.reports()
        emit(self.session / 'reports-before.json', self.initial_reports)
        self.lib = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
        self.lib.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        tb = Timebase()
        ctypes.CDLL('/usr/lib/libSystem.B.dylib').mach_timebase_info(ctypes.byref(tb))
        self.factor = tb.numer / tb.denom
        self.thread = threading.Thread(target=self.collect, daemon=True)
        self.thread.start()
        for _ in range(50):
            if self.latest or self.stop.is_set():
                break
            time.sleep(.1)
        self.check()
        self.event('ready', pid=self.pid, build=self.a.expected_build,
                   settingsSHA256=self.settings_hash, noProfilerAttach=True)

    def reports(self):
        result = []
        for base in [Path('/Library/Logs/DiagnosticReports')]:
            for p in base.glob('*NickExtension*.ips'):
                st = p.stat()
                result.append({'name': p.name, 'mtime': st.st_mtime, 'bytes': st.st_size})
        return result

    def status(self, row, state):
        if not hasattr(self, 'status_root'):
            return
        base_ids = {r['id'] for r in self.h['scanWorkDiagnostics'].get('usbRuns', [])}
        payload = {'time': time.time(), 'state': state, 'stopReason': self.reason,
                   'pid': self.pid, 'build': self.a.expected_build,
                   'footprintBytes': row['phys_footprint'],
                   'lifetimePeakBytes': row['lifetime_max_phys_footprint'],
                   'intervalPeakBytes': row['interval_max_phys_footprint'],
                   'cpuPercent': row.get('cpuPercent'),
                   'authResponseErrorCount': row['health'].get('authResponseErrorCount'),
                   'authMaximumMilliseconds': row['health'].get('authResponseMaximumMilliseconds'),
                   'newUSBRuns': [r for r in row['health']['scanWorkDiagnostics'].get('usbRuns', []) if r['id'] not in base_ids],
                   'mountStartupDiagnostics': row['health'].get('mountStartupDiagnostics', {})}
        tmp = self.status_root / 'status.next'
        emit(tmp, payload)
        os.chmod(tmp, 0o644)
        tmp.replace(self.status_root / 'status.json')

    def collect(self):
        previous = None
        next_aux = 0
        try:
            while not self.stop.is_set():
                tick = time.monotonic()
                usage = Usage()
                if self.lib.proc_pid_rusage(self.pid, 4, ctypes.byref(usage)):
                    raise RuntimeError('proc_pid_rusage failed or process exited')
                h = read_health()
                if hasattr(self, 'kernel_start') and usage.proc_start_abstime != self.kernel_start:
                    raise RuntimeError('Kernel process identity changed')
                self.kernel_start = usage.proc_start_abstime
                row = {'time': time.time(), **{n: getattr(usage, n) for n in FIELDS}, 'health': h}
                if previous:
                    row['cpuPercent'] = 100 * ((usage.user_time + usage.system_time) - previous[1]) * self.factor / 1e9 / (tick - previous[0])
                previous = tick, usage.user_time + usage.system_time
                self.latest = row
                self.status(row, 'collecting')
                with (self.session / 'samples.jsonl').open('a') as f:
                    # Scalar samples at 1 Hz; complete health separately at 10 s and USB changes.
                    f.write(json.dumps({k: v for k, v in row.items() if k != 'health'}) + '\n')
                runs = h['scanWorkDiagnostics'].get('usbRuns', [])
                if tick >= next_aux or runs != getattr(self, 'last_runs', None):
                    self.event('health', health=h)
                    self.last_runs = runs
                    next_aux = tick + 10
                if tick >= getattr(self, 'next_system', 0):
                    vm = subprocess.check_output(['/usr/bin/vm_stat'], timeout=5, text=True)
                    swap = subprocess.check_output(['/usr/sbin/sysctl', '-n', 'vm.swapusage'], timeout=5, text=True)
                    mounts = subprocess.check_output(['/sbin/mount'], timeout=5, text=True)
                    self.event('system', vm_stat=vm, swap=swap.strip(), mounts=mounts)
                    used_swap = swap_used_bytes(swap)
                    if not hasattr(self, 'initial_swap'):
                        self.initial_swap = used_swap
                    if used_swap - self.initial_swap >= GIB:
                        raise RuntimeError('Swap usage grew by 1 GiB; stop load')
                    if available_bytes(vm) < 512 * 1024**2:
                        raise RuntimeError('Free + inactive + speculative memory below 512 MiB')
                    # Bounded df avoids an unbounded filesystem call to an SMB server.
                    backing_path = getattr(self, 'fixture_root', None) or self.a.backing
                    if backing_path:
                        df = subprocess.check_output(['/bin/df', '-Pk', str(backing_path)], timeout=5, text=True)
                        free_kib = int(df.splitlines()[-1].split()[3])
                        if free_kib * 1024 < 50 * GIB:
                            raise RuntimeError('Backing filesystem below 50 GiB free')
                    self.next_system = tick + 10
                if hashlib.sha256(SETTINGS.read_bytes()).hexdigest() != self.settings_hash:
                    raise RuntimeError('Protection settings changed')
                if sum(p.stat().st_size for p in self.session.glob('*.json*')) > 512 * 1024 ** 2:
                    raise RuntimeError('Evidence budget 512 MiB reached')
                problem = gate(row, self.pid, self.a.expected_build,
                               self.a.max_footprint_mib * 1024 ** 2,
                               shutil.disk_usage(self.session).free, time.time())
                if problem:
                    raise RuntimeError(problem)
                self.stop.wait(max(0, 1 - (time.monotonic() - tick)))
        except Exception as exc:
            self.reason = str(exc)
            self.event('safety-stop', reason=self.reason)
            self.stop.set()

    def wait(self, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.check()
            time.sleep(.25)

    def attach(self, image, preparation=None):
        # Mountpoint is known before launch so cleanup also handles interrupted attach.
        mount = preparation or Path('/Volumes') / ('NickRepro-' + uuid.uuid4().hex[:12])
        self.mounts.append(str(mount))
        cmd = ['/usr/bin/hdiutil', 'attach', str(image), '-nobrowse', '-noautoopen', '-mountpoint', str(mount), '-plist']
        if not preparation:
            cmd.append('-readonly')
        data = self.command(cmd, timeout=120)
        plist = plistlib.loads(data)
        found = [e['mount-point'] for e in plist['system-entities'] if 'mount-point' in e]
        if str(mount) not in found:
            raise RuntimeError('Unexpected mountpoint')
        self.event('attach', image=str(image), mount=str(mount), preparation=bool(preparation))
        info = self.command(['/usr/sbin/diskutil', 'info', '-plist', str(mount)], timeout=15)
        (self.session / ('volume-' + mount.name + '.plist')).write_bytes(info)
        return mount

    def detach(self, mount):
        self.command(['/usr/bin/hdiutil', 'detach', str(mount)], timeout=30, safety=False)
        self.mounts.remove(str(mount))
        self.event('detach', mount=str(mount))

    def prepare(self):
        backing = Path(self.a.backing).expanduser().resolve(strict=True)
        if not backing.is_dir() or shutil.disk_usage(backing).free < 50 * GIB:
            raise RuntimeError('Backing needs directory with at least 50 GiB free')
        # Never add data to a real backup target. Only create a fresh private child.
        self.fixture_root = backing / ('NickReproFixture-' + uuid.uuid4().hex)
        self.fixture_root.mkdir(mode=0o700)
        marker = {'schema': 1, 'fixtureID': self.fixture_root.name, 'profile': self.a.profile,
                  'prepared': False, 'created': time.time(), 'images': [],
                  'owner': 'Nick synthetic backup repro only; no real backup contents'}
        self.marker = self.fixture_root / 'fixture.json'
        emit(self.marker, marker)
        self.event('fixture-created', root=str(self.fixture_root))
        profile = PROFILES[self.a.profile]
        for i in range(self.a.images):
            self.check()
            image = self.fixture_root / ('volume-%d.sparsebundle' % i)
            self.command(['/usr/bin/hdiutil', 'create', '-size', str(profile['imageGiB']) + 'g', '-type', 'SPARSEBUNDLE', '-fs', 'Case-sensitive APFS', '-volname', 'NickSynthetic-%d' % i, str(image)], timeout=120)
            prep = self.session / ('populate-%d' % i)
            prep.mkdir()
            mount = self.attach(image, preparation=prep)
            document = b'Nick synthetic document; no executable payload.\n' * 8
            document = document.ljust(profile.get('documentBytes', len(document)), b'.')
            for n in range(profile['entries']):
                if n % 250 == 0:
                    self.check()
                p = mount / fixture_relative(n, profile['depth'])
                p.parent.mkdir(parents=True, exist_ok=True)
                # Nonempty harmless data; root executable classification can cause this
                # to count as a scan candidate too. Actual counters decide coverage.
                p.write_bytes(document)
            for n in range(profile['scripts']):
                if n % 250 == 0:
                    self.check()
                p = mount / fixture_relative(n, profile['depth'], True)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text('#!/bin/sh\n# Synthetic scan fixture. Never executed.\nexit 0\n')
            self.detach(mount)
            marker['images'].append(image.name)
            emit(self.marker, marker)
        marker['prepared'] = True
        emit(self.marker, marker)
        self.event('fixture-ready', root=str(self.fixture_root), details=marker)
        print('Fixture ready:', self.fixture_root, flush=True)

    def load_fixture(self):
        root = Path(self.a.fixture).expanduser().resolve(strict=True)
        marker = json.loads((root / 'fixture.json').read_text())
        if not root.name.startswith('NickReproFixture-') or marker.get('fixtureID') != root.name or not marker.get('prepared'):
            raise RuntimeError('Not a completed harness-owned fixture')
        images = []
        for name in marker['images']:
            if Path(name).name != name or not name.endswith('.sparsebundle'):
                raise RuntimeError('Invalid fixture image')
            image = root / name
            if image.is_symlink() or not image.is_dir():
                raise RuntimeError('Invalid image path')
            images.append(image)
        if not images:
            raise RuntimeError('No prepared images')
        self.fixture_root = root
        self.event('fixture-selected', root=str(root), details=marker)
        return images

    def run(self):
        images = self.load_fixture()
        # Mount output, not diskutil, identifies SMB; diskutil may reject network volumes.
        mounts = subprocess.check_output(['/sbin/mount'], text=True, timeout=5)
        if self.a.require_smb:
            smb_points = [line.split(' on ', 1)[1].split(' (', 1)[0] for line in mounts.splitlines() if ' (smbfs,' in line]
            if not any(self.fixture_root.is_relative_to(Path(p)) for p in smb_points):
                raise RuntimeError('SMB stage requires an already mounted SMB-backed fixture')
        self.wait(30)
        if self.a.stage == 'overlap' and len(images) < 2:
            raise RuntimeError('Overlap requires two distinct prepared images')
        cycles = self.a.cycles if self.a.stage == 'remount' else 1
        for cycle in range(cycles):
            before = self.latest
            existing_runs = before['health']['scanWorkDiagnostics'].get('usbRuns', [])
            if any(r.get('active') for r in existing_runs):
                raise RuntimeError('Existing USB scan active; isolated test cannot start')
            before_ids = {r['id'] for r in existing_runs}
            self.event('stage-start', stage=self.a.stage, cycle=cycle,
                       lifetimePeakBefore=before['lifetime_max_phys_footprint'], usbIDsBefore=sorted(before_ids))
            mounted = [self.attach(images[0])]
            if self.a.volume_probe:
                probe = Path(self.a.volume_probe).resolve(strict=True)
                if not probe.is_file():
                    raise RuntimeError('Probe executable missing')
                result = json.loads(self.command([str(probe), str(mounted[0])], timeout=15))
                self.event('volume-probe-after-attach', result=result)
                print('Volume metadata probe:', json.dumps(result), flush=True)
            if self.a.stage == 'io':
                self.command([sys.executable, '-B', str(Path(__file__).with_name('io_worker.py')),
                    '--read-root', str(mounted[0]), '--scratch-parent', str(self.session),
                    '--seconds', str(self.a.hold_minutes * 60),
                    '--opens-per-second', str(self.a.opens_per_second)],
                    timeout=self.a.hold_minutes * 60 + 10)
            if self.a.stage == 'overlap':
                self.wait(self.a.overlap_delay)
                active = [r for r in self.latest['health']['scanWorkDiagnostics'].get('usbRuns', []) if r['id'] not in before_ids and r.get('active')]
                if not active:
                    raise RuntimeError('First scan not observed active; overlap test invalid, not negative')
                mounted.append(self.attach(images[1]))
            if self.a.stage != 'io':
                self.wait(self.a.hold_minutes * 60)
            runs = [r for r in self.latest['health']['scanWorkDiagnostics'].get('usbRuns', []) if r['id'] not in before_ids]
            self.event('stage-end', stage=self.a.stage, cycle=cycle, usbRuns=runs,
                       scanObserved=bool(runs),
                       lifetimePeakAfter=self.latest['lifetime_max_phys_footprint'],
                       intervalPeakAfter=self.latest['interval_max_phys_footprint'],
                       note='Interval peak read without resetting; not an isolated per-stage maximum')
            if not runs:
                raise RuntimeError('INVALID: no new USB scan record observed; mount is not scan proof')
            for mount in reversed(mounted):
                self.detach(mount)
            self.wait(self.a.recovery_seconds)

    def finish(self):
        # Never delete fixtures automatically, never force-detach or kill Nick.
        for mount in list(reversed(self.mounts)):
            try:
                self.detach(mount)
            except Exception as exc:
                self.event('cleanup-incomplete', mount=mount, error=str(exc))
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=15)
        try:
            emit(self.session / 'after-health.json', read_health())
            emit(self.session / 'reports-after.json', self.reports())
        except Exception as exc:
            self.event('final-read-error', error=str(exc))
        emit(self.session / 'result.json', {'stopReason': self.reason, 'mountsStillNeedingCleanup': self.mounts,
             'settingsUnchanged': hashlib.sha256(SETTINGS.read_bytes()).hexdigest() == self.settings_hash,
             'fixtureRetained': str(getattr(self, 'fixture_root', '')), 'noProfilerAttached': True})
        if self.latest:
            self.status(self.latest, 'stopped' if self.reason else 'finished')
            print((self.status_root / 'status.json').read_text(), flush=True)
        print('Evidence:', self.session, flush=True)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['plan', 'prepare', 'run'], nargs='?', default='plan')
    p.add_argument('--execute', action='store_true', help='Explicitly authorize local prepare/run; no automatic start')
    p.add_argument('--expected-build', default='5112')
    p.add_argument('--session', default='/private/tmp/NickBackupRepro-' + time.strftime('%Y%m%d-%H%M%S'))
    p.add_argument('--backing', help='Existing disposable parent folder, local/USB or already mounted SMB')
    p.add_argument('--fixture', help='Prepared NickReproFixture-* folder')
    p.add_argument('--profile', choices=PROFILES, default='small')
    p.add_argument('--images', type=int, choices=[1, 2], default=2)
    p.add_argument('--stage', choices=['single', 'remount', 'overlap', 'io'], default='single')
    p.add_argument('--require-smb', action='store_true')
    p.add_argument('--volume-probe', help='Optional prepared read-only Foundation eligibility probe executable')
    p.add_argument('--opens-per-second', type=int, choices=[500, 1000, 2000, 5000], default=1000)
    p.add_argument('--cycles', type=int, choices=[2, 3], default=2)
    p.add_argument('--hold-minutes', type=int, default=10)
    p.add_argument('--recovery-seconds', type=int, default=60)
    p.add_argument('--overlap-delay', type=int, default=10)
    p.add_argument('--max-footprint-mib', type=int, default=1024)
    p.add_argument('--total-minutes', type=int, default=30)
    return p


def main():
    a = parser().parse_args()
    if not 1 <= a.hold_minutes <= 30 or not 1 <= a.total_minutes <= 120:
        raise SystemExit('Time limits out of range')
    if not 128 <= a.max_footprint_mib <= 1024 or not 10 <= a.recovery_seconds <= 300 or not 1 <= a.overlap_delay <= 60:
        raise SystemExit('Safety limits out of range')
    if a.action == 'plan' or not a.execute:
        print(json.dumps({'mode': 'PLAN ONLY; no files/images/settings changed', 'arguments': vars(a),
              'profiles': PROFILES, 'requirements': ['sudo for prepare/run', '50 GiB free',
              'same app/active extensions build', 'settings unchanged', 'no profiler attach',
              'SMB must already be mounted; never configure sharing or credentials'],
              'limitations': ['not a real Time Machine backup or snapshot tree',
              'no Backblaze install/transmit automation', 'no system network throttling',
              'root may classify nonempty data as candidates; inspect actual counters',
              '1 GiB ceiling intentionally prevents a 15 GiB reproduction',
              'fixture remains for identical before/after replay; cleanup instructions in README']}, indent=2))
        return
    if (a.action == 'prepare' and not a.backing) or (a.action == 'run' and not a.fixture):
        raise SystemExit('prepare requires --backing; run requires --fixture')
    e = Experiment(a)
    def interrupted(signum, frame):
        e.reason = 'Operator signal ' + str(signum)
        e.stop.set()
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    try:
        e.start()
        if a.action == 'prepare':
            e.prepare()
        else:
            e.run()
    except Exception as exc:
        e.reason = str(exc)
        print('Stopped:', exc, file=sys.stderr)
    finally:
        if hasattr(e, 'settings_hash'):
            e.finish()
    if e.reason:
        raise SystemExit(1)

if __name__ == '__main__':
    main()
