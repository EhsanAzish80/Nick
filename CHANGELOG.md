# Changelog

All notable user-facing changes to Nick are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Nick uses semantic versioning for public releases, with an independent
monotonically increasing macOS bundle build number.

## [Unreleased]

No user-facing changes have been released since 4.5.

## [4.5] - 2026-08-24

### Changed

- Deep Scan recognizes verified SwiftPM artifact caches, XCFramework slices, scratch products, and other structured development outputs without hiding raw evidence.
- Overview and Smart Scan now use the same fresh, version-matched Endpoint Security heartbeat for protection status.
- Download-to-shell detection requires explicit shell execution evidence.

### Fixed

- Apple platform binaries without conventional Team IDs are no longer misclassified as ad-hoc when they satisfy Apple's signature anchor.
- Email attachment heuristics no longer become active findings for incompatible file formats.
- Signed shell interpreters cannot automatically legitimize attacker-controlled LaunchAgent arguments.
- Attention descriptions now interpolate the actual issue counts.

### Verification

- 424 automated tests executed: 420 passed, 4 platform-dependent tests were skipped, and 0 failed.
- The app, Endpoint Security extension, Network Filter extension, and uninstaller all report version 4.5, build 426.
- An installed deep scan examined 96,555 files with no concrete threat verdicts and two remaining review findings for locally installed Zoom updater LaunchAgents.
- The signed package and disk image are Developer ID signed, notarized, stapled, and accepted by Gatekeeper.

## [4.4] - 2026-08-23

### Added

- Network Activity now explains the responsible app, destination type, port context, observation reason, and the scope of each allow action.
- Overview identifies the specific protection or scan result that needs attention and provides a direct route to review it.

### Changed

- Deep Scan now separates concrete malware signatures from contextual behavior matches, uses rule metadata for severity, and presents total matches separately from findings that need review.
- Process signing and threat columns resolve live evidence instead of leaving every process as unknown; pending and unavailable evidence are labeled explicitly.
- Alert context and remediation wording now distinguish observations, historical evidence, missing files, and actionable threats.

### Fixed

- Deep Scan continues when the user changes sections, prevents overlapping starts, cooperates with cancellation, and avoids mutating results after cancellation.
- Reduced false positives from application caches, developer repositories, Homebrew wrappers, canonical path aliases, and broad behavior rules without suppressing concrete or critical signatures.
- Canonical rule/path deduplication prevents duplicate findings for aliases such as `/tmp` and `/private/tmp`.
- Ignored paths and trusted contexts can suppress only non-critical behavioral findings; malware signatures and critical evidence remain visible.

### Verification

- 406 automated tests executed: 402 passed, 4 platform-dependent tests were skipped, and 0 failed.
- The app, Endpoint Security extension, Network Filter extension, and uninstaller all report version 4.4, build 422.
- The signed package and disk image are Developer ID signed, notarized, stapled, and accepted by Gatekeeper.

## [4.3] - 2026-08-23

### Changed

- The menu bar shield is rendered as an explicit green, orange, or red image so macOS cannot replace its attention state with a black template icon.
- Active-alert badges and menu bar state now use the same actionable, user-facing evidence as the Alerts view.
- Sparkle performs daily automatic update checks while leaving installation under user control.

### Fixed

- Resolved or reclassified alerts no longer leave a stale badge when the Active list is empty.
- Alerts for disappeared files and ended processes remain historical evidence without being counted as current threats.
- Check for Updates now invokes Sparkle directly and records update discovery and completion results for diagnosis.

### Verification

- 373 automated tests executed: 369 passed, 4 platform-dependent tests were skipped, and 0 failed.
- The app, Endpoint Security extension, Network Filter extension, and uninstaller all report version 4.3, build 421.
- The signed package and disk image are notarized, stapled, and accepted by Gatekeeper.

## [4.2] - 2026-08-23

### Added

- Alert explanations now identify the originating parent application when that evidence is available, including clearer context for shells, build tools, SSH, Git, curl, and other dual-use developer commands.
- The menu bar icon now reflects protection state with green, orange, and red attention levels.

### Changed

- Signed software in installed locations is described as a rule match that needs review rather than a confirmed malware identity.
- Reverse-shell and living-off-the-land detections now require stronger command, parent, signing, path, or network context before escalating.
- Ransomware detection recognizes application-managed encrypted cache traffic and requires corroborating behavior before quarantine.
- Persistence results distinguish a missing executable from an unsigned or malicious executable.

### Fixed

- Prevented common developer workflows and signed updaters from repeatedly producing high-confidence malware wording without supporting evidence.
- Prevented WhatsApp encrypted media-cache writes from being quarantined solely because the files have high entropy.
- Quarantine now validates evidence hashes, preserves duplicate samples with unique vault records, and never deletes the original when isolation fails.
- Restore and remediation paths now fail safely when a file has disappeared or no longer matches the recorded evidence.

### Verification

- 373 automated tests executed: 369 passed, 4 platform-dependent tests were skipped, and 0 failed.
- The app, Endpoint Security extension, Network Filter extension, and uninstaller all report version 4.2, build 420.
- The signed package and disk image are notarized, stapled, and accepted by Gatekeeper.

## [4.1] - 2026-08-12

### Added

- Runtime Compare captures local before-and-after snapshots of processes,
  persistence, listening ports, connections, system extensions, and sensor
  health.
- Deterministic comparison explains observed changes, evidence quality, and
  visibility limitations without presenting the result as compliance proof.
- Sanitized Markdown and JSON support bundles can be previewed and exported
  without modifying the locally stored comparison.
- Interrupted comparisons can be resumed after a restart on the same Mac.

### Changed

- Runtime snapshots and imports now have explicit event, record, file-size,
  retention, and observation-time limits.
- Cross-restart comparison ignores short-lived process churn and prefers the
  active system-extension generation when macOS reports overlapping records.
- Provider health is part of comparison accuracy: unavailable evidence creates
  a visibility warning instead of unsupported added or removed findings.
- Process enumeration retries the macOS process-table sizing race rather than
  treating a transient `ENOMEM` result as an empty inventory.

### Fixed

- Prevented duplicate process and extension identities from crashing a
  follow-up comparison.
- Prevented hundreds of misleading process-removal findings after restart.
- Prevented retiring system-extension records from creating false Nick
  extension state changes.

### Verification

- 349 automated tests executed: 345 passed, 4 platform-dependent tests were
  skipped, and 0 failed.
- A real baseline, restart, and follow-up comparison reduced the prior 496
  noisy findings to 40 evidence-backed observations with no process flood or
  false Nick extension transitions.
- The signed package and disk image are notarized, stapled, and accepted by
  Gatekeeper.

## [4.0.1] - 2026-07-30

### Changed

- Scam Guardian is now observation-only and cannot interrupt ordinary network
  traffic.
- Network policy configuration is versioned; missing, stale, or invalid
  configuration fails open.
- Scam Guardian status and documentation now distinguish destination
  monitoring from active blocking.
- Endpoint Security and Network Extension setup continues to require current
  runtime health before protection is shown as ready.

### Fixed

- Prevented the Network Filter from disrupting browsers, Git, developer tools,
  AirDrop, Handoff, and other legitimate connections.
- Corrected network observations so known-rule matches remain visible for
  review without being converted into drop verdicts.

### Verification

- All 321 automated tests passed; 4 platform-dependent tests were skipped.
- The signed package and disk image were notarized, stapled, and accepted by
  Gatekeeper.

## [4.0] - 2026-07-27

### Added

- Endpoint Security system extension with authenticated XPC health reporting.
- Network Extension content filter for Scam Guardian.
- Email attachment screening for supported Apple Mail and Outlook locations.
- Guided protection setup and native uninstaller.
- Threat Timeline, ransomware sentinels, file-integrity monitoring, and
  privacy-permission monitoring.
- Signed package, disk-image, notarization, and Sparkle release tooling.

### Changed

- Alerts now explain detected files, rule matches, source context, recommended
  action, and available remediation.
- Smart Scan reports verified runtime health instead of assuming installed
  components are active.
- Background monitoring, caches, persistence, and UI refresh work are bounded
  to reduce system impact.
- Continuous integration now builds every shipping component, runs tests with
  coverage, and reports to Codecov and SonarCloud.

### Security

- Network enforcement is allowlist-first and fails open if configuration cannot
  be read.
- Downloaded network rules require an Ed25519-signed envelope. Publication
  remains disabled until the production signing key is embedded and verified.
- Obsolete Python pickle-loading tools were removed.

## [3.0] - 2026-06-02

### Added

- YARA-based malware scanning.
- Endpoint Security integration groundwork.
- Expanded system-health and security reporting.

See the [Nick 3.0 release](https://github.com/EhsanAzish80/Nick/releases/tag/V3.0).

## [1.2] - 2026-05-25

### Added

- Behavioral scoring and reporting improvements.

See the [Nick 1.2 release](https://github.com/EhsanAzish80/Nick/releases/tag/v1.2).

## [1.1] - 2026-05-25

### Changed

- Detection hardening and interface improvements.

See the [Nick 1.1 release](https://github.com/EhsanAzish80/Nick/releases/tag/v1.1).

## [1.0] - 2026-05-24

- Initial public release.

[Unreleased]: https://github.com/EhsanAzish80/Nick/compare/v4.4.0...HEAD
[4.4]: https://github.com/EhsanAzish80/Nick/releases/tag/v4.4.0
[4.3]: https://github.com/EhsanAzish80/Nick/releases/tag/v4.3.0
[4.2]: https://github.com/EhsanAzish80/Nick/releases/tag/v4.2.0
[4.1]: https://github.com/EhsanAzish80/Nick/releases/tag/v4.1.0
[4.0.1]: https://github.com/EhsanAzish80/Nick/releases/tag/v4.0.1
[4.0]: https://github.com/EhsanAzish80/Nick/releases/tag/v4.0.0
[3.0]: https://github.com/EhsanAzish80/Nick/releases/tag/V3.0
[1.2]: https://github.com/EhsanAzish80/Nick/releases/tag/v1.2
[1.1]: https://github.com/EhsanAzish80/Nick/releases/tag/v1.1
[1.0]: https://github.com/EhsanAzish80/Nick/releases/tag/v1.0
