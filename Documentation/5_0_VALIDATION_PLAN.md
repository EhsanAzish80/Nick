# Nick 5.0 Validation Plan

This plan prepares the 5.0 release gates. It does not authorize publishing,
tagging, changing an appcast, or describing a gate as passed before its
evidence is recorded.

## Evidence record

For every run record the date, macOS and hardware, Nick version/build and
commit, extension versions, the complete `systemextensionsctl list` output,
settings that affect the result, exact workload,
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

## One ordered Phase 7b session

Run this table from top to bottom on one Mac. Start with one fresh signed and
notarized candidate whose build is at least 5015. Use that exact candidate for
steps 1–11, then update it through Sparkle to the next numbered build. Do not
substitute a rebuilt package without restarting the session record. Every
row's result is written as **Pass**, **Fail**, or **Blocked**, with readings or
an evidence path; a checkmark without evidence is not a result.

| Step | Gate and required evidence | Result |
|---:|---|---|
| 1 | **Freeze candidate.** Record commit, marketing/build versions, PKG/DMG SHA-256, notarization and stapling results, macOS/hardware, settings, and start time. | Pending |
| 2 | **Install and prove active versions.** Install over the existing accepted build. Record Diagnostics' app, Endpoint Security and Network Filter builds plus the complete unedited `systemextensionsctl list` output. All three must equal the candidate build. | Pending |
| 3 | **Phase 4 soak re-run.** Use Safari/Finder for ten minutes, download/open a harmless file, clean-build Nick in Xcode, run the bounded Spotlight import, and continue to 30 minutes. Capture extension PID and health at 0/10/20/30 minutes, event rates, deadline misses, CPU, responsiveness and the final 35-minute extension log. PID must remain stable; deadline misses must not increase; health must stay fresh; no event type may exceed 10,000/s twice; extension CPU must remain below 15% outside the build. | Pending |
| 4 | **Phase 5a store re-run.** Before restart, record incident and dismissal counts and root-store hashes. Restart the app and both extensions. Confirm no incident/tombstone loss, no replay notifications, root ownership/modes, and app-only reads with writes occurring only through authenticated XPC. | Pending |
| 5 | **Phase 5b durable-evidence re-run.** Create a harmless monitored-file change, restart app and extension, confirm the pending FIM record survives, acknowledge only that record, and confirm settings survive. The previously tombstoned Nick protected-path incident must not return. | Pending |
| 6 | **Phase 5c authorization re-run.** For trusted process, allow-once, quarantine restore, Dismiss and Always Allow: cancel once and verify no mutation, then approve and verify only the selected action. Re-run the refused-form harness and authorization-right tamper/repair check. Record prompts, root-store hashes and final right definition. | Pending |
| 7 | **Phase 6b self-protection re-run, excluding uninstall.** Verify Nick/Sparkle/Apple-installer identities; test protected-file `rm`, rename destination, and in-bundle write/create denial with visible incidents; preserve a red incident while flooding over 100 low-value events and confirm the per-rule cap plus visible eviction count; verify the ESET acknowledgement. Keep Finder uninstall for step 14. | Pending |
| 8 | **Writer matrix.** Safari, Finder, Mail and `curl` each write the safe EICAR fixture. Each writer produces one incident and notification, survives restart, and does not duplicate on reload. | Pending |
| 9 | **Phishing.** Navigate to the reserved test destination. Record one network incident and notification without blocking unrelated traffic. | Pending |
| 10 | **Camera/microphone.** Activate each device with a known app. Each state transition appears once within the documented interval; do not claim per-app attribution unless evidence contains it. | Pending |
| 11 | **Detection, performance and F1–F8.** Run the safe regression fixtures: local-address/port classification, honest one-signal text/timestamps/signing, protected LOLBin evidence, update-event coalescing, mixed-version retry message, retention resistance, AUTH p50/p99/deadlines, event loss, CPU/memory/energy/log volume, CMake `.make`, sync/backup/database/editor workloads, symlink/file swaps, burst writes, renamed binary, fake Team ID, settings tampering, extension deactivation and quarantine restore boundaries. Never use live malware or credentials. | Pending |
| 12 | **Sparkle update to next build.** From the candidate, discover and install the next higher signed/notarized staging build. Verify notification, in-app state and menu-bar badge; genuine update interaction clears the badge. Record one coalesced maintenance incident, no red self-protection incident, Diagnostics builds, and complete `systemextensionsctl list` output after update. | Pending |
| 13 | **End-of-candidate version proof.** Record end time, app and both active extension builds in Diagnostics, complete `systemextensionsctl list`, extension health/deadlines, incident/severity totals, evictions and retained logs. Versions must match the updated build. | Pending |
| 14 | **Finder uninstall last.** Move Nick.app to the current user's real Trash and verify the visible notice and documented partial-uninstall behavior. Reinstall only as required for the measurements below; use the complete uninstaller after all measurements finish. | Pending |
| 15 | **4.6.3 alert-count baseline.** Install released 4.6.3 and run the fixed workload below. Export counts and severities. | Pending |
| 16 | **5.0 learning off.** Install the accepted updated 5.0 candidate, prove active versions again, keep learning off, and repeat the identical workload. | Pending |
| 17 | **5.0 learning on, pending.** Enable learning with authorization but with no active learned entry; repeat the workload. Protected evidence must be unchanged. | Pending |
| 18 | **5.0 learning active.** Activate one eligible review-tier pattern using two authenticated decisions from different incidents; repeat the workload. Only that review-tier pattern may be de-prioritized, never hidden. | Pending |
| 19 | **Automated final gate and closeout.** On the exact final candidate run unit/detection tests, repository validation, YARA lint, documentation drift and the **~17k files (cap 120k)** benign corpus. Record final checksums and every failure. | Pending |

## Fixed alert-count workload for steps 15–18

Start each run from the same documented alert state. Do not clear or dismiss
items during the workload. Keep notification severity, network protection,
scan roots and exclusions identical. Reboot when changing installed builds,
prove the app and extension versions, and allow five idle minutes before the
measurement.

Run the same 20-minute sequence each time:

1. Five idle minutes with Safari and Finder open.
2. In Terminal, run `git pull` in the same Git fixture, `brew update`, and
   `swift build` in the same separate Swift-package fixture. Do not use Nick's
   repository as the Swift-package fixture.
3. Perform a clean Xcode Release build of Nick.
4. Deep Scan the same projects fixture.
5. Use Finder to copy and rename ordinary documents and save one file
   atomically from the same editor.
6. Run the same safe F1–F8 fixtures.

Export incidents immediately after each run. Record total new incidents,
counts by severity and rule, occurrence counts, notifications, protected
findings, dismissed/suppressed results, evicted-count changes and duplicates.
Any new high or critical developer-workload alert is investigated; trust is
never widened merely to make the comparison pass.

## Pass rule

Every checkbox needs an observed result in the private progress record. A
failure is fixed and rerun, or explicitly accepted by Ehsan with rationale.
The three deferred Phase 1 gates—Sparkle installation, genuine badge clearing,
and the 4.6.3 alert comparison—cannot be waived for 5.0.
