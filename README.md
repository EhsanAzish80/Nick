# Nick

Nick is an open-source macOS security application that combines Endpoint
Security monitoring, malware scanning, behavioral correlation, system
hardening checks, email attachment inspection, and optional network filtering.
Detection and analysis run locally on the Mac.

Current release: **4.0 (build 404)**

[CI](https://github.com/EhsanAzish80/Nick/actions/workflows/ci.yml) |
[SonarCloud](https://sonarcloud.io/summary/new_code?id=EhsanAzish80_Nick) |
[Codecov](https://codecov.io/gh/EhsanAzish80/Nick) |
[Security policy](SECURITY.md) |
[Contributing](CONTRIBUTING.md)

## What Nick 4.0 includes

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
URLs, query strings, or payloads. Allowlisted apps and domains take precedence,
and the filter fails open when its configuration cannot be read.

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

## Architecture

Nick ships as a signed application bundle containing two system extensions:

```text
Nick.app
├── SwiftUI application
│   ├── SecurityEngine and MonitorCoordinator
│   ├── Smart Scan, Alerts, Timeline, Quarantine, and Reports
│   └── Setup, settings, Sparkle updates, and maintenance
├── NickExtension.systemextension
│   ├── Endpoint Security client
│   ├── YARA and behavioral scanning
│   ├── Email Guard, ransomware, integrity, and privacy monitors
│   └── authenticated XPC service
└── NickNetFilter.systemextension
    ├── Network Extension content filter
    ├── Scam Guardian and signed blocklist policy
    └── privacy-safe health and block events

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

1. Download the notarized Nick disk image from
   [GitHub Releases](https://github.com/EhsanAzish80/Nick/releases).
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
| Network Extension | NickNetFilter | Optional Scam Guardian destination filtering |
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

Version 4.0 release notes are in
[Packaging/Release/v4.0.0/RELEASE_NOTES.md](Packaging/Release/v4.0.0/RELEASE_NOTES.md).

## Quality gates

GitHub Actions builds all shipping targets, runs the test suite with coverage,
uploads the Xcode result bundle to Codecov, converts Xcode coverage for
SonarCloud, and runs CI-based SonarCloud analysis.

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

- [Architecture and security boundaries](ARCHITECTURE.md)
- [User and operator guide](Documentation/USER_GUIDE.md)
- [Development and CI guide](Documentation/DEVELOPMENT.md)
- [Release checklist](Documentation/RELEASE_CHECKLIST.md)
- [Roadmap](Documentation/ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy and audit notes](SECURITY.md)

## Project status

Nick 4.0 source, tests, signed package, and manual-download disk image are
prepared. A release is not considered complete until the exact published build
is installed on a clean Mac and its Endpoint Security, Email Guard, Scam
Guardian block test, update, performance, quarantine, and uninstall flows are
verified.

## License

Nick is licensed under the
[GNU Affero General Public License v3.0](LICENSE).

## Acknowledgments

Nick uses YARA and builds on public macOS security research, including the work
of the Objective-See Foundation and the wider macOS security community.
