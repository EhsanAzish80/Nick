# Changelog

All notable user-facing changes to Nick are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Nick uses semantic versioning for public releases, with an independent
monotonically increasing macOS bundle build number.

## [Unreleased]

No user-facing changes have been released since 4.0.1.

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

[Unreleased]: https://github.com/EhsanAzish80/Nick/compare/v4.0.1...HEAD
[4.0.1]: https://github.com/EhsanAzish80/Nick/releases/tag/v4.0.1
[4.0]: https://github.com/EhsanAzish80/Nick/releases/tag/v4.0.0
[3.0]: https://github.com/EhsanAzish80/Nick/releases/tag/V3.0
[1.2]: https://github.com/EhsanAzish80/Nick/releases/tag/v1.2
[1.1]: https://github.com/EhsanAzish80/Nick/releases/tag/v1.1
[1.0]: https://github.com/EhsanAzish80/Nick/releases/tag/v1.0
