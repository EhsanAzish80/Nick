<p align="center">
  <img src="NickIcon.png" width="144" alt="Nick app icon">
</p>

<h1 align="center">Nick</h1>

<p align="center">
  Native, local-first protection that explains what happened, why it matters,
  and what to do next.
</p>

<p align="center">
  <a href="https://github.com/EhsanAzish80/Nick/actions/workflows/ci.yml"><img src="https://github.com/EhsanAzish80/Nick/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI status"></a>
  <a href="https://github.com/EhsanAzish80/Nick/releases/latest"><img src="https://img.shields.io/github/v/release/EhsanAzish80/Nick?display_name=tag&sort=semver" alt="Latest release"></a>
  <a href="https://codecov.io/gh/EhsanAzish80/Nick"><img src="https://codecov.io/gh/EhsanAzish80/Nick/branch/main/graph/badge.svg" alt="Code coverage"></a>
  <a href="https://sonarcloud.io/summary/new_code?id=EhsanAzish80_Nick"><img src="https://sonarcloud.io/api/project_badges/measure?project=EhsanAzish80_Nick&metric=alert_status" alt="SonarCloud quality gate"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/EhsanAzish80/Nick" alt="AGPL-3.0 license"></a>
  <img src="https://img.shields.io/badge/macOS-26%2B-black?logo=apple" alt="macOS 26 or later">
</p>

<p align="center">
  <a href="https://github.com/EhsanAzish80/Nick/releases/latest"><strong>Download Nick</strong></a>
  ·
  <a href="https://3nsofts.com/nick">Website</a>
  ·
  <a href="Documentation/README.md">Documentation</a>
  ·
  <a href="SUPPORT.md">Support</a>
</p>

## About Nick

Nick is an open-source macOS security application built to make advanced
protection understandable. It combines Apple's Endpoint Security and Network
Extension frameworks with YARA malware scanning, behavioral correlation,
system-hardening checks, email attachment inspection, quarantine, and
human-readable alerts.

Detection and analysis run locally on the Mac. Nick does not upload browsing
history, file contents, process activity, or security telemetry to a hosted
analysis service.

Unlike a simple scanner, Nick continuously connects evidence from processes,
files, persistence, privacy access, and network activity. A single unusual
event can be explained without automatically being called malware; stronger,
correlated evidence can be blocked, quarantined, and presented with a clear
next action.

Nick also includes Runtime Compare: a local, read-only workflow for capturing
the Mac before and after a restart, installation, removal, MDM migration, VPN
change, or security configuration change. It compares stable evidence rather
than raw PIDs and timestamps, reports missing sensor visibility explicitly, and
exports sanitized Markdown or JSON support bundles.

## Protection layers

| Layer | What it does |
|---|---|
| Real-Time Protection | Observes process and file activity through Apple's Endpoint Security framework. |
| Malware Scanner | Uses YARA rules for on-demand, real-time, email, and external-volume scanning. |
| Behavioral Detection | Correlates process, persistence, filesystem, privacy, and network signals. |
| Scam Guardian | Observes phishing and lookalike destinations through a fail-open Network Extension. |
| Email Guard | Scans supported Apple Mail and Outlook attachment locations. |
| Ransomware Shield | Watches sentinel files and suspicious high-volume file changes. |
| System Audit | Checks SIP, FileVault, Gatekeeper, firewall, updates, XProtect, and persistence. |
| Threat Timeline | Keeps a bounded, searchable record of relevant security activity. |
| Quarantine | Re-verifies and isolates actionable files while preserving recovery information. |
| Performance | Explains disk usage and offers reviewed, opt-in cleanup actions. |
| Runtime Compare | Captures before-and-after runtime evidence and exports sanitized support bundles. |

### Endpoint Security

The `NickExtension` system extension uses Apple's Endpoint Security framework
to observe file and process activity. It performs YARA and behavioral checks,
reports activity to the main app, and can deny a confirmed malicious file
before execution.

### Malware scanning and quarantine

- Vendored libyara 4.5.5 with curated macOS rules.
- On-demand, real-time, email attachment, and external-volume scanning.
- Confidence-aware results: heuristic matches are shown for review; only
  actionable matches can be blocked or quarantined.
- Quarantine re-scans the selected file before moving it.
- Alerts show the file name, path, matching rule, source, recommended action,
  and relevant controls.

### Behavioral detection

Nick correlates process, persistence, network, file, and privacy signals rather
than treating every unusual event as malware. Coverage includes suspicious
parent-child chains, living-off-the-land tools, reverse-shell patterns,
unsigned executables in writable locations, persistence changes, and unexpected
camera or microphone activity.

### Scam Guardian

The optional `NickNetFilter` system extension uses Apple's Network Extension
content-filter APIs to evaluate connection destinations against signed rules
and lookalike-domain checks. It does not inspect page contents or store full
URLs, query strings, or payloads. Version 4.0.1 operates in observation-only
mode: suspected destinations are reported for review, but the extension does
not drop ordinary application traffic. Missing, stale, or invalid
configuration also fails open.

### Email Guard

Email Guard monitors supported Apple Mail and Outlook attachment locations
through the Endpoint Security extension. New attachments are scanned before
Nick reports them as safe. Full Disk Access is required for protected mail
data.

### System and privacy monitoring

- SIP, FileVault, Gatekeeper, firewall, XProtect, and update checks.
- LaunchAgent, LaunchDaemon, login-item, cron, and other persistence checks.
- Process and active-connection views with human-readable context.
- File-integrity and ransomware sentinel monitoring.
- Privacy permission and capture-device change monitoring.
- Bounded Threat Timeline and exportable security reports.

### Performance and maintenance

- Disk-usage analysis and reviewed cleanup recommendations.
- Background work uses reduced cadence when Nick is not active.
- Bounded caches, event stores, and scan concurrency.
- A bundled native uninstaller removes Nick, its protection components,
  generated data, settings, and installed applications.

### Runtime Compare and network diagnostics

Runtime Compare captures two bounded snapshots of the same Mac and explains
what changed across:

- processes and persistent startup items;
- listening ports and observed connection destinations;
- Endpoint Security and Network Extension inventory;
- provider and sensor health.

Comparisons can pause across a restart and resume after Nick opens again.
Findings distinguish observed evidence, inference, and information Nick could
not confirm. Cross-restart process churn is suppressed, overlapping retiring
extension generations are coalesced, and incomplete providers produce a
visibility warning instead of unsupported findings.

Support bundles are generated locally. Sanitized export redacts identifying
paths, hostnames, addresses, and account-specific values while retaining the
technical structure needed for diagnosis. Runtime Compare does not remediate
MDM state, certify compliance, collect fleet data, or enforce network policy.

## Product principles

- **Local by default.** Detection and correlation happen on the Mac.
- **Evidence before alarm.** Unusual behavior is explained without pretending
  that every anomaly is malware.
- **Actionable alerts.** Alerts identify the relevant file, process, rule,
  source, recommended response, and available controls.
- **Verified protection.** Installation alone is never shown as a healthy
  protection state; components must report current runtime health.
- **User-controlled remediation.** Cleanup, quarantine, permissions, and
  optional network filtering remain visible decisions.

## Architecture

Nick ships as a signed application bundle containing two system extensions:

```text
Nick.app
├── SwiftUI application
│   ├── SecurityEngine and MonitorCoordinator
│   ├── Smart Scan, Alerts, Timeline, Quarantine, and Runtime Compare
│   └── Setup, settings, Sparkle updates, and maintenance
├── NickExtension.systemextension
│   ├── Endpoint Security client
│   ├── YARA and behavioral scanning
│   ├── Email Guard, ransomware, integrity, and privacy monitors
│   └── authenticated XPC service
└── NickNetFilter.systemextension
    ├── Network Extension content filter
    ├── Scam Guardian and signed destination policy
    └── privacy-safe health and observation events

Nick Uninstaller.app
└── guided removal and cleanup
```

The main architectural rule is that installation is not treated as proof of
protection. Smart Scan and setup show a green state only after the relevant
component reports current health.

For implementation details and trust boundaries, see
[ARCHITECTURE.md](ARCHITECTURE.md).

## Requirements

- macOS 26 or later.
- Xcode 26 or later for source builds.
- A Mac capable of running macOS 26.
- Apple-approved Endpoint Security and Network Extension entitlements for
  signed system-extension builds.

## Installation

### Published release

The current stable release is **Nick 4.3 (build 421)** for macOS 26 and later.

1. Download the notarized Nick disk image from
   [the latest GitHub release](https://github.com/EhsanAzish80/Nick/releases/latest).
2. Open the disk image and run the signed installer package.
3. Launch Nick from `/Applications`.
4. Follow the setup walkthrough. macOS requires explicit user approval for
   system extensions, Network Extensions, and Full Disk Access.
5. Complete Smart Scan and confirm that each enabled protection reports current
   health.

The disk image is a presentation wrapper around the installer package. Sparkle
updates use the signed package directly.

### Permissions

| Approval | Used by | Purpose |
|---|---|---|
| Endpoint Security system extension | NickExtension | Real-time process and file monitoring |
| Network Extension | NickNetFilter | Optional Scam Guardian destination monitoring |
| Full Disk Access | Nick and NickExtension | Protected system and mail attachment locations |
| Notifications | Nick | User-facing threat notifications |

Nick cannot silently grant these approvals. The setup walkthrough opens the
correct macOS pane and waits for verified component health.

## Building from source

Clone and open the checked-in Xcode project:

```sh
git clone https://github.com/EhsanAzish80/Nick.git
cd Nick
open Nick.xcodeproj
```

Build without signing:

```sh
xcodebuild build \
  -project Nick.xcodeproj \
  -scheme Nick \
  -destination "platform=macOS" \
  CODE_SIGN_IDENTITY="" \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=NO
```

Run the complete test suite with coverage:

```sh
xcodebuild test \
  -project Nick.xcodeproj \
  -scheme Nick \
  -destination "platform=macOS" \
  -enableCodeCoverage YES \
  -resultBundlePath TestResults.xcresult \
  CODE_SIGN_IDENTITY="" \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=NO
```

Unsigned builds are compile and unit-test evidence only. They cannot prove that
Endpoint Security or Network Extension installation works.

## Release and update distribution

The production release pipeline is documented in
[Packaging/README.md](Packaging/README.md). In summary:

- `Packaging/release.sh` builds, signs, notarizes, staples, and validates the
  installer package.
- `Packaging/build-dmg.sh` creates the notarized manual-download disk image.
- Sparkle reads `https://3nsofts.com/nick/appcast.xml`.
- The appcast enclosure must reference the exact, unmodified signed package.
- Manual website and GitHub downloads may use the disk image.

Version 4.3 release notes are in
[Packaging/Release/v4.3.0/RELEASE_NOTES.md](Packaging/Release/v4.3.0/RELEASE_NOTES.md).

## Quality gates

GitHub Actions builds all shipping targets, runs the test suite with coverage,
uploads the Xcode result bundle to Codecov, and, when `SONAR_TOKEN` is
configured, converts Xcode coverage and runs CI-based SonarCloud analysis.

Project coverage measures production targets only; test-source targets are
excluded so executing the tests cannot inflate the headline percentage. The
current project target is a 15% honest baseline. Patch coverage is reported as
an informational signal while coverage expands around legacy UI and
platform-integration code.

Repository settings required for hosted analysis:

- `CODECOV_TOKEN` repository secret.
- `SONAR_TOKEN` repository secret.
- SonarCloud Automatic Analysis disabled so CI-based coverage is used.

Vendored libyara sources and generated build, package, and result artifacts are
excluded from SonarCloud ownership and coverage calculations.

## Uninstalling

Run `/Applications/Nick Uninstaller.app`. The uninstaller guides removal of
active protection, application data, preferences, installed components, and
both application bundles. macOS can retain a disabled privacy-list row after
the executable is removed; that row is system-owned UI state and does not mean
the extension remains installed.

## Documentation

- [Engineering case study: Building a Local macOS Endpoint Security Monitor in Swift](https://3nsofts.com/insights/building-local-macos-endpoint-security-monitor-swift)
- [Documentation index](Documentation/README.md)
- [Changelog](CHANGELOG.md)
- [Architecture and security boundaries](ARCHITECTURE.md)
- [User and operator guide](Documentation/USER_GUIDE.md)
- [Development and CI guide](Documentation/DEVELOPMENT.md)
- [Release checklist](Documentation/RELEASE_CHECKLIST.md)
- [Roadmap](Documentation/ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [Support](SUPPORT.md)
- [Security policy](SECURITY.md)
- [Security audit record](Documentation/SECURITY_AUDIT.md)

## Project status

Nick 4.3 is the current production release. Every future release remains gated
on clean-Mac validation of Endpoint Security, Email Guard, Scam Guardian,
updates, performance, quarantine, and uninstall behavior.

## License

Nick is licensed under the
[GNU Affero General Public License v3.0](LICENSE).

## Acknowledgments

Nick uses YARA and builds on public macOS security research, including the work
of the Objective-See Foundation and the wider macOS security community.
