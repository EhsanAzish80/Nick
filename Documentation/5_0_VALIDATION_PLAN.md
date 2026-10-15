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

The YARA gate is reported as the **benign executable corpus (cap 120k)** and
always includes the exact candidate count selected on that machine. The count
varies with the installed macOS and application inventory; do not reuse a
historical approximate count as if it were a threshold. YARA lint always runs.
The full corpus runs under the repository's approved path policy and at the
final release gate.

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
| 7 | **Phase 6b self-protection re-run, excluding uninstall.** Verify Nick/Sparkle/Apple-installer identities; test protected-file `rm`, rename destination, and in-bundle write/create denial with visible incidents. Each operation has its own protected incident with correct delete/move/modify wording. Test `pkill`, `kill -9`, `kill -STOP`, SIGTERM, SIGINT, SIGHUP and SIGQUIT from the same user against Nick-signed app/helper processes: the signal is denied within the AUTH deadline and a protected incident identifies the sender. Repeat from root and record which senders macOS 27.x exempts. User Quit, logout/shutdown and a Sparkle update must carry an authenticated intentional-exit token and create no unexpected-termination incident. Kill the Endpoint Security extension and verify sysextd relaunch creates one same-boot protection-gap incident; reboot creates one informational resumed-after-restart record; authorized deactivation creates its immediate incident and no later gap incident. Kill only the app and verify the unexpected-exit path. Replay or roll back a heartbeat sequence and verify it is rejected. A new occurrence reopens reviewed, resolved or hidden protected evidence and notifies; repeated occurrences coalesce, update the count, and produce at most one replacing notification per incident every ten minutes. Exact event redelivery does not change the count or notify. Preserve a red incident while flooding over 100 low-value events and confirm the per-rule cap plus visible eviction count; verify the ESET acknowledgement. Keep Finder uninstall for step 14. | Pending |
| 8 | **Writer matrix.** Safari, Finder, Mail and `curl` each write the safe EICAR fixture into Downloads, Desktop or Mail Downloads. Each writer produces one incident and notification, survives restart, and does not duplicate on reload. Custom download folders are outside the 5.0 completed-write scope. | Pending |
| 9 | **Phishing observation (5.0 timebox).** Navigate to the reserved exact-blocklist destination. Network Activity must classify it as **Known dangerous destination**, status **Observed**, and say the app **tried to connect** and Nick recorded but did not block the attempt. It must offer only the existing destination/domain allowance, never persistent app trust, and unrelated traffic must remain unaffected. Network-to-incident persistence and notification are deferred to 5.0.1. | Pending |
| 10 | **Camera/microphone.** Activate each device with a known app. The event-driven CMIO/CoreAudio listener must show exactly one active transition and one inactive transition after the app stops using the device, and the active observation must notify once. Device-client evidence may identify the owning app; otherwise a signed foreground app may be shown only as context and the UI must say that this is not proof of ownership. The inactive transition resolves and updates the same device incident rather than leaving an active claim behind. | Pending |
| 11 | **Detection, performance and F1–F8.** Run the safe regression fixtures: local-address/port classification, honest one-signal text/timestamps/signing, protected LOLBin evidence, update-event coalescing, mixed-version retry message, retention resistance, AUTH p50/p99/deadlines, event loss, CPU/memory/energy/log volume, CMake `.make`, sync/backup/database/editor workloads, symlink/file swaps, burst writes, renamed binary, fake Team ID, settings tampering, extension deactivation and quarantine restore boundaries. Never use live malware or credentials. | Pending |
| 12 | **Sparkle update to next build.** From the candidate, discover and install the next higher signed/notarized staging build. Verify notification, in-app state and menu-bar badge; genuine update interaction clears the badge. Record one coalesced maintenance incident, no red self-protection incident, Diagnostics builds, and complete `systemextensionsctl list` output after update. | Pending |
| 13 | **End-of-candidate version proof.** Record end time, app and both active extension builds in Diagnostics, complete `systemextensionsctl list`, extension health/deadlines, incident/severity totals, evictions and retained logs. Versions must match the updated build. | Pending |
| 14 | **Finder uninstall last.** Move Nick.app to the current user's real Trash and verify the visible notice and documented partial-uninstall behavior. Reinstall only as required for the measurements below; use the complete uninstaller after all measurements finish. | Pending |
| 15 | **4.6.3 alert-count baseline.** Install released 4.6.3 and run the fixed workload below. Export counts and severities. | Pending |
| 16 | **5.0 learning off.** Install the accepted updated 5.0 candidate, prove active versions again, keep learning off, and repeat the identical workload. | Pending |
| 17 | **5.0 learning on, pending.** Enable learning with authorization but with no active learned entry; repeat the workload. Protected evidence must be unchanged. | Pending |
| 18 | **5.0 learning active.** Activate one eligible review-tier pattern using two authenticated decisions from different incidents; repeat the workload. Only that review-tier pattern may be de-prioritized, never hidden. | Pending |
| 19 | **Automated final gate and closeout.** On the exact final candidate run unit/detection tests, repository validation, YARA lint, documentation drift and the **benign executable corpus (cap 120k)**. Record the exact selected-file count, final checksums and every failure. | Pending |

## Active-enforcement upgrade matrix

Run every supported channel from the same installed lower build while its
Endpoint Security extension is active. The destination must be a higher build
containing both higher-build extensions. Record the old and new complete
`systemextensionsctl list`, installer/update logs, UI result, incident changes,
and whether protection was ever disabled.

| Channel | Supported for 5.0 | Required result | Result |
|---|---|---|---|
| Installer.app GUI | Yes | Higher build installs atomically; both extensions replace and activate; no blocked self-update incident. | Pending |
| `/usr/sbin/installer -pkg … -target /` | Yes | Same result from the command-line PackageKit path while the old extension enforces. | Pending |
| Sparkle package update | Yes | Signed staging appcast installs the higher package, clears the update badge after genuine interaction, and produces at most one informational maintenance incident. | Pending (ordered-session step 12) |
| MDM/Intune package deployment | **Not supported in 5.0** | The experimental profiles are not release assets and have not been validated in a managed tenant. Do not claim or score this channel as passed. | Not applicable |

The successful same-build 5016 Installer.app reinstall proves the immediate
`com.apple.shove` correction, but it does not replace this lower-to-higher
matrix.

## Upgrade safety-valve proposal

An update must not depend solely on a permanent list of installer executable
identifiers compiled into the already-installed extension. Before 5.0 ships,
implement and threat-model a short-lived update lease with these properties:

1. Nick.app requests the existing protection Authorization Services right and
   sends the external form over authenticated XPC.
2. The root-owned settings store records a single-use lease with a monotonic
   expiry (maximum ten minutes), current console UID, expected Nick Team ID,
   current build, and strictly higher destination build.
3. While the lease is valid, tamper protection permits replacement only of the
   exact Nick application and bundled-extension destinations. The responsible
   process must still validate to Apple's PackageKit/installd chain or Nick's
   validated Sparkle chain; arbitrary writes, deletes and renames remain
   blocked.
4. The lease is consumed by the first successful replacement, cleared on
   timeout/restart, and cannot be extended without fresh authorization. Every
   creation, use, expiry and rejection becomes durable audit evidence.
5. A failed update leaves the old app runnable. Package layout and preflight
   must not remove `/Applications/Nick.app` before the replacement is ready.

The install-channel matrix must pass both with ordinary validated maintenance
identity and with a deliberately omitted nonessential allow-list identity while
the authorized lease is active. That second test proves the safety valve is
independent of the stale allow-list rather than merely widening it.

Implementation gate: Sparkle's `Autoupdate` identity is deliberately absent
from the permanent maintenance list. A Sparkle update from this candidate to a
strictly newer candidate must prompt once for Nick's protection right, create a
root-owned lease, complete the atomic replacement, consume the lease, and leave
an audit record. Cancelling the prompt, using the same/lower build, restarting
the extension, waiting more than ten minutes, targeting any path outside the
exact Nick application bundle, or using an unvalidated actor must leave the
installed app unchanged. Confirm `state/update-lease.json` is root-owned and
mode `0600` after the test.

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
