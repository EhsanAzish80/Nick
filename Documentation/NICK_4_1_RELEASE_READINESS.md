# Nick 4.1 Release Readiness

Assessment date: 2026-08-12

Status: **Build 416 passed automated, distribution, and real restart-comparison gates**

The exact build 413 artifacts passed Apple distribution, in-place upgrade, and
post-reboot extension validation, but the first real Runtime Compare follow-up
capture exposed a duplicate-identity crash. Build 413 must not be published.
Build 414 fixed that crash, but a real reboot comparison exposed an unavailable
process inventory followed by 949 misleading removal findings. Build 414 must
not be published. Build 415 also remains rejected after a real restart comparison
showed 496 exported findings: successful but non-equivalent cross-boot process
inventories still produced hundreds of informational removals, and overlapping
retiring/active system-extension records produced false state transitions.
Build 416 suppresses point-in-time process churn across boot sessions, prefers
the active record when macOS reports overlapping extension generations, and
continues to fail closed when provider evidence is incomplete
and retries the process-table sizing race that returned `ENOMEM`.

## Automated evidence completed

- Full `Nick` test suite: 343 tests executed, 339 passed, 4 skipped, 0 failed.
- The four skips are existing source-fixture checks that macOS cannot read from
  the workspace without Full Disk Access; they are not Runtime Compare test
  failures.
- `Nick.app` line coverage: 14.03% (4,907 of 34,979 executable lines). This is
  the product-target figure from `/tmp/Nick-4.1-ReleaseGate.xcresult`; test
  bundle coverage is intentionally not counted as product coverage.
- Runtime Compare has deterministic unit coverage for stable identities,
  PID/timestamp noise, extension parsing, findings, partial visibility,
  ordering, sanitization, configurable bounded retention, persistence reload,
  same-Mac import, reboot/resume workflow, evidence resolution, cancellation,
  partial sample failure, export limits, and a 100,000-event aggregation load.
- Runtime network evidence is capped at 25,000 distinct records. Omitted
  distinct records change provider health to `partial` and are reported to the
  user rather than silently discarded.
- A single stored snapshot is capped at 25 MB; imports and support bundles are
  capped at 50 MB.
- The 100,000-event aggregation fixture completed in approximately 1.4 seconds
  on the development Mac while preserving the 25,000-record ceiling.
- Unsigned Release builds succeeded for `Nick`, `NickExtension`,
  `NickNetFilter`, `NickHelper`, and `NickUninstaller`.
- `git diff --check` passes.

## Build 413 distribution and upgrade evidence

> **Rejected candidate:** retain the following evidence for traceability, but
> do not distribute these build 413 artifacts.

- Installed app identity: marketing version `4.1`, build `413`.
- `codesign --verify --deep --strict` passes for the installed app and all
  nested code; Gatekeeper accepts it as notarized Developer ID software.
- PKG notarization submission `c26c3e66-17dd-4630-a0b7-a1594d9c67df` was
  accepted, stapled, validated, and accepted by Gatekeeper.
- PKG SHA-256:
  `b3cf50e139c0097306e7e7d32e7f33348fe3f0da4857f7e52bf5bde84ed215ad`.
- Sparkle enclosure signature:
  `+gCfcYjhyjd8doy1+vc4JoHXkgU7uOL5BOv//60lxeK1Av5qTb1XePtprKIC0mS2edLwkRvZSBn4r01ndnrwDQ==`
  with length `15637869`.
- DMG notarization submission `1c704761-900e-4d99-a19c-9e568d56ece6` was
  accepted, stapled, validated, and accepted by Gatekeeper.
- DMG SHA-256:
  `4b1b4189b01ccdefcd03d3bf60b538e5988d5be6eb6461b9c05287cf946c63c5`.
- In-place installation over build 412 succeeded without uninstalling Nick.
- `NickExtension` and `NickNetFilter` build 413 both reached
  `[activated enabled]`; superseded versions are waiting for normal reboot
  cleanup.
- After startup work settled, Nick, NickExtension, and NickNetFilter each
  sampled at 0.0% CPU. Resident memory was approximately 165 MB, 46 MB, and
  17 MB respectively.
- GitHub returned HTTP 200 in 0.45 seconds and `git ls-remote` succeeded while
  both extensions were active.
- No Endpoint Security initialization failure, extension crash, network denial,
  or database error appeared in the five-minute release runtime log. macOS 27
  emitted CoreUI window-control and one AppKit layout-recursion warning; these
  did not disrupt protection or connectivity.
- A 30-second Instruments Time Profiler recording attached to the installed
  build completed normally with the app responsive. The trace is retained for
  this release audit at `/tmp/Nick-4.1-413-TimeProfiler.trace`.

## Build 413 rejection and source remediation

- A real post-reboot follow-up capture crashed on the main thread with
  `EXC_BREAKPOINT` in Swift's assertion failure path.
- Unified logging identified the exact assertion:
  `Fatal error: Duplicate values for key:` for two
  `TrustEvaluationAgent` process records with the same stable path.
- Root cause: Runtime Compare used `Dictionary(uniqueKeysWithValues:)` for
  system-derived process and comparison indexes. Real process, persistence, or
  extension inventories can legitimately contain duplicate stable identities.
- Source now coalesces duplicates deterministically instead of trapping. The
  process collector preserves a non-empty path and comparison indexes retain
  the record with the lexicographically smallest stable record ID.
- Regression tests cover duplicate process and extension identities. The full
  focused Runtime Compare suite passes after the fix.

## Build 414 candidate evidence

> **Rejected candidate:** distribution mechanics passed, but comparison
> accuracy did not. Do not distribute build 414.

- Build 414 includes deterministic duplicate coalescing in process collection
  and Runtime Compare indexes; duplicate process and extension regression tests
  pass.
- Full suite result: 343 tests executed, 339 passed, 4 intentional source
  fixture skips, 0 failed. Result bundle:
  `/tmp/Nick-4.1-414-ReleaseGate.xcresult`.
- PKG notarization submission `c3f8acb5-0a25-41f6-b2f6-936fd0983762`
  was accepted, stapled, validated, and accepted by Gatekeeper.
- PKG SHA-256:
  `9310aa57dc930ff43803c62aa312e427f40ac43dd0956e4f78a5f7c9a89cf7e5`.
- Sparkle enclosure signature:
  `3BsHyM8ogYCX/h3oRYBaCmyFwveZnk+J5AZc1eVcw1ulXorJnUo6PAAJYR9daCi249pYQ1OfshjHq8En8HbUCg==`
  with length `15633256`.
- DMG notarization submission `d91ad630-3478-4873-be69-91a5c4967f74`
  was accepted, stapled, validated, and accepted by Gatekeeper.
- DMG SHA-256:
  `7e10f1efe8f83e693e1bb694c8dcb870e8ab4d0ef9cdecc7496dc761b15a0299`.
- Expanded installer inspection contains zero physical AppleDouble `._*` files.
  Stapled package tickets can appear as virtual extended-attribute entries in
  `pkgutil --payload-files`; `pkgutil --expand-full` verifies the actual payload.

## Build 414-415 rejection and build 416 remediation

- The real post-reboot build 414 export completed without crashing and correctly
  recognized a different boot session.
- Its follow-up Processes provider failed with
  `sysctl(KERN_PROC_ALL) failed with errno 12`, leaving zero follow-up process
  records while the baseline contained 1,164.
- The old comparator ignored provider health and produced 949 unsupported
  `Process no longer observed` findings.
- Build 416 suppresses all added/removed findings when either relevant provider
  is partial or unavailable. Unavailable providers produce only a quality
  warning. Partial persistence and extension inventories may report only state
  changes backed by matching records in both captures, with an explicit
  limitation.
- Process enumeration now retries `ENOMEM` up to five times using a freshly
  sized buffer with headroom.
- Regression tests cover unavailable process evidence and partial connection
  evidence. Full suite result: 347 tests total, 343 passed, 4 intentional skips,
  0 failed. Result bundle: `/tmp/Nick-4.1-ProviderAccuracy.xcresult`.

## Build 416 final acceptance

- Full suite: 349 tests executed, 345 passed, 4 platform-dependent tests
  skipped, 0 failed.
- PKG notarization submission `4d565201-ac60-4ed9-a0ce-dc82d69a34a4` was
  accepted, stapled, validated, and accepted by Gatekeeper.
- PKG SHA-256:
  `a47b7446302c951cb18936dc41e0f4b22b7fbde8f770434a635cce091809456f`.
- Sparkle enclosure signature:
  `2hbomU3p0cOL0StU4nRBfL0uYF5hSzrucW1jM/lT/z6Uw2pS8nvtfj223mBEMcXbZBZqrpVlcFL0Fmsuj9enAA==`
  with length `15636565`.
- DMG notarization submission `63233a90-b95a-4e4d-9dee-ffa87ecf7786` was
  accepted, stapled, validated, and accepted by Gatekeeper.
- DMG SHA-256:
  `e5b80437be29c297e5736e862f729e0f3b87ca710f6522292c0398003c71a8f6`.
- All four Nick bundles report marketing version `4.1`, build `416`.
- The real build 416 baseline/restart/follow-up export completed with 40 total
  findings instead of build 415's 496. It contained no cross-restart process
  flood and no false Nick extension transition.
- Both Nick extensions were active and enabled after restart. Network Filter
  health was available in both captures; Endpoint Security moved from partial
  before restart to available afterward and was accurately reported as a
  visibility change.

## Remaining post-release validation

1. **Clean-Mac validation:** build 416 passed upgrade and restart comparison on
   the development Mac. A separate clean Mac should still exercise first-run
   permissions and complete uninstall.
2. **Extended integration validation:** deterministic tests do not replace realistic
   capture tests covering reboot, permissions loss, active Endpoint Security
   and Network Extension providers, high connection volume, and partial sensor
   availability.
3. **Performance monitoring:** idle CPU, resident memory, connectivity, a
   30-second release-build Time Profiler recording, and a real Runtime Compare
   capture are accepted; continue monitoring on additional hardware.
4. **Clean-system acceptance:** build 413 signatures, notarization,
   stapling, Gatekeeper, extensions, connectivity, and package upgrade behavior
   are validated on the development Mac. A clean-Mac install and complete
   uninstall still require acceptance testing.
5. **Coverage:** 14.03% product coverage is a truthful baseline, not a high-coverage release
   claim. Codecov policy should reflect an intentional target and the critical
   4.1 paths should gain integration and performance coverage.

## Publication sequence

1. Commit and push the accepted source and release metadata.
2. Publish GitHub tag `v4.1.0` with the notarized build 416 DMG and checksums.
3. Upload the exact build 416 PKG to the website URL recorded in the appcast.
4. Verify the PKG URL, then publish the appcast and test an update from 4.0.1.
