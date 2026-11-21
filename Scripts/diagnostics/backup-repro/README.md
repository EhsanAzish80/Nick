# Local backup investigation — prepared, not started

This harness is for the maintainer’s Mac Studio. It changes no Nick source or settings, never executes fixture scripts, never attaches a profiler, never configures SMB, and never touches real Time Machine/Backblaze data. It is not a fix or a claim that #122 is resolved. Keep PR #127 and the original 5111 artifacts unchanged. These files are local preparation only, not committed/pushed into that PR.

## Tomorrow's first command

From the Nick checkout:

```sh
/usr/bin/python3 -B Scripts/diagnostics/backup-repro/repro.py plan
```

The default is always plan only. `prepare` and `run` also do nothing without `--execute`. No automation starts overnight. Start with the small fixture and inspect actual counters before scaling. Do not run all commands below unattended.

### Prepare a disposable local fixture

Choose a parent on local storage with at least 50 GiB free; `/private/tmp` is suitable if that free-space check passes. This creates **two distinct** case-sensitive APFS sparsebundles, each populated at a private preparation mount. It may take time and generate ordinary Nick observations. Preparation is recorded separately from measured scans.

```sh
sudo /usr/bin/python3 -B Scripts/diagnostics/backup-repro/repro.py prepare --execute --backing /private/tmp --profile small --total-minutes 30
```

Record the printed `NickReproFixture-...` path. Each image contains 10,000 nonempty harmless document files and 2,000 short scripts in deep paths. Scripts are never executed. Root may classify nonempty documents as scan candidates too: rely on Nick’s actual `scanned` count, not the intended count. Fixtures are retained for identical before/after replay; a partial preparation has `prepared: false` and cannot run.

### Single scan, then controlled remounts, then overlap

Replace `FIXTURE_PATH` with that exact fixture directory. Each command creates a fresh, private evidence session and verifies app/both active extension builds, health and settings. Do not execute these in parallel. The measured stage refuses to start while any pre-existing USB scan is active; wait for natural completion rather than stopping your real backups.

```sh
sudo /usr/bin/python3 -B Scripts/diagnostics/backup-repro/repro.py run --execute --fixture FIXTURE_PATH --stage single --hold-minutes 10 --total-minutes 15
sudo /usr/bin/python3 -B Scripts/diagnostics/backup-repro/repro.py run --execute --fixture FIXTURE_PATH --stage remount --cycles 2 --hold-minutes 10 --total-minutes 30
sudo /usr/bin/python3 -B Scripts/diagnostics/backup-repro/repro.py run --execute --fixture FIXTURE_PATH --stage overlap --overlap-delay 10 --hold-minutes 10 --total-minutes 15
```

Overlap uses two different images; if Nick’s first scan is not observed active when the second should attach, the test stops as **invalid**, not a negative reproduction. Health publication may lag a short scan. Remounts are controlled ten-minute windows rather than a claim to reproduce the reporter’s exact hourly backup timing. Unmounting can cancel an unfinished scan; the report must retain that distinction. An unmount/remount of the same image may overlap old cancellation briefly; observed `usbRuns` determine whether it happened.

### Reads/mmaps and generated modified-file churn

Only after scan-only baselines, optionally run:

```sh
sudo /usr/bin/python3 -B Scripts/diagnostics/backup-repro/repro.py run --execute --fixture FIXTURE_PATH --stage io --opens-per-second 1000 --hold-minutes 5 --total-minutes 10
```

This reads/mmaps at most 2,000 synthetic files from the mounted fixture and rewrites one 64 MiB generated chunk every ten seconds in the evidence session’s temporary scratch directory. It reports achieved rate, removes its chunk, and never invokes real backup software. Python's signing/identity differs from Backblaze; this does not reproduce third-party credential validation. Keep this phase separate to avoid attributing its effects to enumeration. It does not replace the earlier signed-reader Test A.

## Closer SMB and long-scan reproduction

No existing SMB mount was identified during preparation. This is a prerequisite, not an invitation to alter your production backup destination. Select an already-mounted **disposable SMB share/folder**, with adequate permissions and at least 50 GiB free. Mount/authentication remains manual; never put credentials in command arguments, config or evidence. The harness does not enable file sharing or modify firewall/network shaping.

Prepare on that folder using `--backing /Volumes/YOUR_TEST_SHARE/DISPOSABLE_FOLDER`. First use `--profile small`; after reviewing the results, `medium` has 100,000 documents + 10,000 scripts/image, and `large` has 1,000,000 documents + 30,000 scripts/image. Scaling is a separate deliberate action, not automatic. Two large images mean two million generated documents in total. Preparation may hit its time budget and leave a partial fixture; that is not a failed Nick test.

For every SMB run add `--require-smb`; it rejects a local/USB fixture mislabeled as SMB. Use the same single/remount/overlap matrix. `--hold-minutes` allows up to 30 minutes per mount and `--total-minutes` up to 120 minutes. Review after each stage. No SMB speed or minimum scan duration is guaranteed. Record whether the scan was genuinely long enough and whether overlap actually occurred. A slow USB fixture can be prepared in the same way without `--require-smb`, with the backing explicitly recorded as USB, not SMB.

These are synthetic APFS backup-like trees, **not actual Time Machine snapshots, roles or history**. Adding snapshots, real backup writes or network throttling is not implemented; those need a separately reviewed next stage if the existing matrix is insufficient.

## Hard stops and cleanup

- Default and maximum extension physical footprint: **1 GiB** (may be lowered). The goal is to catch growth safely, not reach the reporter’s 15 GiB.
- At least **50 GiB free** on evidence and backing filesystems.
- Stop if swap grows by **1 GiB** from baseline or free + inactive + speculative pages total less than **512 MiB**. This page sum is a coarse safety proxy, not the OS memory-pressure level.
- Stop on extension PID/build change, stale sampling/health, settings hash change, **512 MiB evidence budget**, command timeout or total time budget.
- Ctrl-C or a `STOP` file in the printed evidence session stops the harness and attempts normal detach of **only its own mountpoints**. The directory is root-private, so create the marker from another Terminal with `sudo touch /private/tmp/EXACT_SESSION/STOP`.
- Never force-unmount, kill/restart Nick or change protection settings automatically. Detach may fail or a network operation may stall at the OS level; `result.json` lists remaining mountpoints. Stopping the harness does not instantly reclaim Nick’s retained memory. Stop further tests if it does not recover.
- Generated images are retained for A/B replay, not silently deleted. After confirming no harness mount remains, remove only the exact `NickReproFixture-...` directory you created. Do not use real backup volume names or broad globs. No cleanup of user backups is automated.
- Keep the owning Terminal open; foreground shell interruption invalidates continuity. No unattended overnight workload is configured.

## Evidence and interpretation

Evidence sessions are mode 0700 and contain local mount paths/health; sanitize before sharing. They include exact command/mount chronology, diskutil volume metadata and UUIDs, settings hash, before/after health and report inventory, 1 Hz passive kernel V4 rusage, and full USB records on changes. A 10 s auxiliary stream records VM/swap and mounts. CPU uses the kernel timebase. No `vmmap`, `heap`, `leaks`, `footprint`, `sample`, `spindump`, task ports, allocation logging or Security-policy edits.

Lifetime and interval kernel peak fields are captured, including before/after each stage. The interval peak is **not reset** and must not be labeled an isolated stage maximum. An unchanged lifetime peak only bounds this phase below the existing high-water mark. `usbRuns` currently has no volume identity: correlate isolated mount events with new run IDs, and mark ambiguity during overlap. Volume UUIDs in the harness evidence do not retroactively prove which run belongs to which mount.

Compare identical retained fixtures, stage/rate/duration/settings and backing across baseline/candidate builds using `--expected-build`. Account for preparation and warm caches. Memory growth tracking scan activity is correlation; it does not identify autorelease retention without allocation evidence. No new kill is established from process continuity plus OS-report evidence, not from zero late-attempt counters alone. A directory report inventory is not an exhaustive termination detector. Actual long scan, Backblaze-equivalent actor and real Time Machine behavior remain separate evidence gates.

## Validation performed during preparation

`validate_harness.py` checks pure parser/path/safety behavior and compares ctypes V4 layout with a tiny C program compiled against the installed macOS SDK. A passive `proc_pid_rusage` call targets **the validator itself**, never Nick. This is harness validation, not an Xcode app test or load test. No image was created, mounted or populated during preparation. Runtime orchestration, remote SMB, cleanup under device failure and the stress workloads remain to be validated tomorrow.

Summarize a finished evidence session without rerunning anything:

```sh
sudo /usr/bin/python3 -B Scripts/diagnostics/backup-repro/summarize.py /private/tmp/EXACT_SESSION
```

## Next slower-backing stage (2026-11-21)

LaCie was inspected as USB, non-solid-state, with roughly 1.5 TiB available. This is local HDD backing, not SMB. The separate Backup volume shares the physical device, so concurrent real backup I/O is a confound; do not change or stop it automatically.

The `sustained` profile creates one image when used with `--images 1`: 40,000 synthetic 128 KiB documents plus 2,000 short scripts, depth 10, about 4.88 GiB document content inside a 12 GiB logical image. All candidates total below the existing 50,000 scan cap. No fixture script is executed. Preparation is capped at ten minutes; measured run keeps the previous two-minute hold/five-minute total limit. OS caches are not purged. A short scan remains an insufficient reproduction, not a pass for the reported long workload.
