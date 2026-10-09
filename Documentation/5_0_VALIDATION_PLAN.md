# Nick 5.0 Validation Plan

This plan prepares the 5.0 release gates. It does not authorize publishing,
tagging, changing an appcast, or describing a gate as passed before its
evidence is recorded.

## Evidence record

For every run record the date, macOS and hardware, Nick version/build and
commit, extension versions, settings that affect the result, exact workload,
start/end time, raw counts, severity counts, failures, and links or paths to
the retained output. Use the same Mac and workload for comparisons. A failed
or interrupted run is evidence, not a pass.

The YARA gate is reported consistently as the **~17k files (cap 120k)** benign
corpus. YARA lint always runs. The full corpus runs under the repository's
approved path policy and at the final release gate.

## YARA dependency verification

Nick's shipping engine vendors libyara 4.5.5. The official PyPI JSON index was
rechecked on 2026-10-09: yara-python 4.5.4 remains the newest published release
and no 4.5.5 release exists. CI therefore remains pinned to 4.5.4 as the closest
published Python gate binding. Recheck the official index before changing the
Python or vendored pin; do not request a nonexistent matching package.

## Alert-count comparison

Measure four configurations:

1. Nick 4.6.3, the released baseline.
2. Nick 5.0 with verdict learning off.
3. Nick 5.0 with verdict learning on but no active learned entry.
4. Nick 5.0 with one eligible review-tier pattern activated by two separate,
   authenticated incident decisions.

Start each run from the same documented alert state. Do not clear or dismiss
items during the workload. Keep notification severity, network protection,
scan roots and exclusions identical. Reboot when changing installed builds,
verify the expected app and extension build numbers, and allow five idle
minutes before starting.

Run this fixed 20-minute workload in the same order:

1. Five idle minutes with Safari and Finder open.
2. In Terminal: run `git pull` in the same recorded Git fixture, `brew update`,
   and `swift build` in the same separate Swift-package fixture (which must
   contain its own `Package.swift`). These are workload fixtures, not commands
   to run from Nick's repository root.
3. Perform a clean Xcode Release build of Nick.
4. Deep Scan the same projects fixture.
5. Use Finder to copy and rename ordinary documents; save one file atomically
   from an editor.
6. Run the safe F1-F8 regression fixtures described below. Never use live
   malware or real credentials.

Export incidents immediately after each run. Record total new incidents,
counts by severity and rule, occurrence counts, notifications, protected
findings, dismissed/suppressed results, evicted-count changes, and duplicate
incidents. Compare the 5.0 runs against 4.6.3 and against one another. Learning
may lower only eligible review-tier results after two different incidents; it
must not hide them or change protected evidence. Any new high or critical
developer-workload alert is investigated before release. Do not widen trust to
make the measurement pass.

## Consolidated real-Mac checklist

Use signed, notarized Release packages. Capture app/extension build numbers
before and after every installation.

### Core monitoring and parked gates

- [ ] **Writer matrix:** Safari, Finder, Mail and `curl` each write the safe
      EICAR fixture. Each writer produces one incident and one notification,
      remains present after restart, and does not duplicate on reload.
- [ ] **Phishing:** navigate to the reserved test destination. It produces one
      network incident and one notification without blocking unrelated traffic.
- [ ] **Camera/microphone:** activate each device with a known app. Each state
      transition appears as one incident within the documented interval; no
      per-app attribution is claimed unless the evidence contains it.
- [ ] **Sparkle 5.0 to later 5.0:** install the first staging build manually,
      update to a higher signed/notarized staging build through Sparkle, verify
      app and both extension build numbers, one coalesced informational
      maintenance incident, and no red self-protection incident.
- [ ] **Update reminder:** background discovery shows the notification, visible
      in-app update state and menu-bar badge. Opening the genuine update UI
      clears the badge; merely relaunching or dismissing unrelated UI does not.

### F1-F8 regression set

- [ ] F1: RFC1918 and link-local destinations are classified as local, not
      external.
- [ ] F2: mDNS 5353 and the maintained local-discovery ports are not described
      as uncommon; an `adb` connection to a LAN device does not create an
      occurrence flood.
- [ ] F3: a one-signal incident for a known app never claims multiple signals
      or an unknown process.
- [ ] F4: every contributing signal timestamp is within the incident lifecycle;
      none precedes `firstSeen` after merge or persistence reload.
- [ ] F5: LOLBin evidence reaches a final signing state rather than remaining
      `pending`; the high-value `osascript … with administrator privileges` plus
      `/tmp` installer pattern remains visible.
- [ ] F6: a validated Nick/Sparkle/Apple-installer upgrade collapses to one
      informational maintenance incident.
- [ ] F7: during a deliberately created mixed app/extension version window,
      protected actions show a clear retry message rather than failing silently.
- [ ] F8: more than 100 low-value findings do not evict an unresolved red
      incident; coalescing is by rule plus actor identity, one rule occupies at
      most its configured share, and Diagnostics shows the evicted count.

### Performance, resilience and adversarial gates

- [ ] Endpoint Security AUTH latency p50/p99 and timeouts meet the documented
      budget under idle and build/sync load.
- [ ] Deadline misses do not increase; queue-overflow and event-loss counters
      remain zero in the normal workload and are visible under a stress fixture.
- [ ] CPU, memory, energy and log volume are recorded idle and during Xcode,
      sync and Deep Scan workloads.
- [ ] Ransomware heuristics remain quiet for sync, backup, database, editor and
      build workloads, including CMake `.make` generation.
- [ ] Symlink swap, file replacement, burst writes, renamed binary, fake Team
      ID, settings tampering and extension-deactivation fixtures fail closed or
      raise the expected protected incident.
- [ ] Quarantine restore preserves safe ownership/mode, refuses symlinked
      parents and never restores setuid/setgid bits.
- [ ] Finder uninstall, the documented in-app uninstaller, protected-file `rm`,
      rename destination and in-bundle write checks match the accepted Phase 6
      behavior.
- [ ] The ~17k files (cap 120k) benign corpus, detection fixtures, unit tests,
      repository validation, YARA lint and documentation drift gate pass on the
      final candidate.

## Pass rule

Every checkbox needs an observed result in the private progress record. A
failure is fixed and rerun, or explicitly accepted by Ehsan with rationale.
The three deferred Phase 1 gates—Sparkle installation, genuine badge clearing,
and the 4.6.3 alert comparison—cannot be waived for 5.0.
