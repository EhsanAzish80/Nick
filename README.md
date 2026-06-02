<p align="center">
  <img src="NickIcon.png" alt="Nick" height="100">
</p>
<h3 align="center">Open-source macOS security suite with on-device AI threat scoring</h3>
<p align="center">
  One app. Six layers of protection. Zero cloud dependency. Read every line of code.
</p>
<p align="center">
  <img src="https://img.shields.io/badge/platform-macOS%2026%2B-000000?style=flat&logo=apple" alt="macOS 26+">
  <img src="https://img.shields.io/badge/swift-6.0-F05138?style=flat&logo=swift" alt="Swift 6.0">
  <img src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat" alt="AGPL-3.0">
  <img src="https://img.shields.io/badge/tests-273%20passing-brightgreen?style=flat" alt="273 tests passing">
  <img src="https://github.com/EhsanAzish80/Nick/actions/workflows/ci.yml/badge.svg" alt="CI">
  <a href="https://sonarcloud.io/summary/new_code?id=EhsanAzish80_Nick"><img src="https://sonarcloud.io/api/project_badges/measure?project=EhsanAzish80_Nick&metric=alert_status" alt="Quality Gate"></a>
  <a href="https://codecov.io/gh/EhsanAzish80/Nick"><img src="https://codecov.io/gh/EhsanAzish80/Nick/branch/main/graph/badge.svg" alt="Coverage"></a>
  <img src="https://img.shields.io/github/stars/EhsanAzish80/Nick?style=flat" alt="Stars">
</p>
<p align="center">
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#installation">Installation</a> •
  <a href="#building-from-source">Build</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#roadmap">Roadmap</a>
</p>

---

## Why Nick?

macOS ships with solid built-in security — XProtect, Gatekeeper, SIP — but these defenses are signature-based and reactive. They catch known threats after Apple adds a definition. They don't catch:

- **Behavioral threats** — a signed app quietly exfiltrating your keychain
- **Living-off-the-land attacks** — `curl` piping to `bash`, `osascript` running obfuscated scripts
- **Persistence backdoors** — new LaunchAgents installed silently by compromised software
- **Tunnel detection** — reverse shells, unexpected SSH forwarding, SOCKS proxies
- **Zero-day exploits** — novel malware that no signature database has seen yet

Existing tools either cost $60+/year (Norton, Intego), require installing 5-6 separate utilities (Objective-See's excellent but fragmented suite), or are enterprise-only (CrowdStrike, SentinelOne).

**Nick is one app that replaces six tools**, with the only open-source on-device AI behavioral threat scoring engine for macOS. No cloud. No subscription. No trust required — the code is right here.

---

## Features

### �️ Endpoint Security Extension (v3.0)
Nick's system extension uses Apple's Endpoint Security framework to intercept `AUTH_EXEC`, `AUTH_OPEN`, `AUTH_CREATE`, `AUTH_MMAP`, and `AUTH_COPYFILE` events at the kernel level — **blocking malicious files before they execute**, not after. Registered via `SMAppService`; communicates with the main app over a private XPC connection.

### �🔍 System Integrity Audit
Continuously verifies your Mac's security posture:
- SIP (System Integrity Protection) status
- FileVault encryption state
- Gatekeeper configuration
- Application Firewall status and rules
- XProtect definition freshness
- TCC database integrity
- `sudo` configuration and PATH integrity

### 🛡️ Persistence Monitor
Watches every known persistence mechanism on macOS and alerts on changes:
- `/Library/LaunchDaemons` and `/Library/LaunchAgents`
- `~/Library/LaunchAgents`
- Login Items
- Cron jobs and periodic scripts
- System Extensions and kernel extensions
- Browser extensions (Safari, Chrome, Firefox)

### 🌐 Network Watchdog
Real-time visibility into what's connecting where:
- Active connections mapped to processes
- Listening port detection (unexpected services)
- Reverse shell detection (shell processes with outbound connections)
- SSH tunnel and port forwarding identification
- DNS query monitoring for known malicious domains
- Unexpected VPN/proxy process detection

### 🔬 Process Auditor
Identifies suspicious runtime behavior:
- Unsigned or ad-hoc signed binaries executing
- Processes running from `/tmp`, `/var/tmp`, or hidden directories
- LOLBin abuse detection (`curl | bash`, `osascript` with obfuscated payloads, `openssl` reverse connections)
- Suspicious parent-child process chains
- Unexpected child processes from GUI apps

### 🧬 YARA Scanner
On-demand and real-time file scanning:
- **libyara 4.5.2** static engine embedded directly in the ES event pipeline — every cache-miss file is evaluated before an allow/deny decision is made
- Bundled macOS-specific rulesets: adware, backdoors, ransomware, stealers
- Community-contributed rules via pull requests
- Deep Scanner: on-demand full-system YARA crawl, battery-aware, with live progress
- USB/external media auto-scan on mount
- Per-file scan timeout (10 s) prevents stalls on malformed files
- Heuristic analysis: entropy scoring, Mach-O header inspection, embedded URL/IP extraction

### 📷 Camera & Microphone Sentinel
Detects unauthorized access to your camera and microphone in real time:
- Monitors all CoreMediaIO video devices for unexpected activation
- Monitors CoreAudio input devices for unsanctioned recording
- Attributes device activation to the most-recently-launched non-system process
- Elevates severity to high when an unsigned binary is found accessing media hardware
- Baseline-delta approach: only alerts on new activations, not ongoing expected usage

### 📡 Logging & SIEM Integration (v1.2)
Nick's functional logging pipeline sends alerts to your existing security infrastructure with zero configuration overhead:
- **Formats:** Key=Value, JSON, CEF — pick one or pipe them yourself
- **Outputs:** Local log file with daily rotation, HTTP POST webhook (Splunk HEC, AWS, PagerDuty, any HTTPS endpoint), stdout
- **MDM-configurable** — all settings readable from the managed defaults domain (`com.ehsanazish.nick`)

No syslog. No OpenTelemetry. No dedicated developer required.

### 🧠 AI Behavioral Scoring (The Differentiator)
On-device CoreML pipeline for behavioral threat correlation. Rule-based scoring is live; the CoreML inference model activates once trained on real-world signal data collected via opt-in telemetry.
- Individual signals are noisy. Correlated behavioral signals are actionable.
- `curl` downloading a binary to `/tmp` = medium risk
- That binary executing unsigned 2 seconds later = high risk
- That binary opening an outbound connection to a raw IP on port 443 = critical
- **15 correlation rules** including `browser_to_shell`, `office_to_shell`, `raw_ip_outbound`, advanced LOLBin patterns, and more
- Natural-language alert explanations powered by on-device Foundation Models (macOS 26+)
- No data ever leaves your Mac

---

## Architecture

```
┌──────────────────────────────────────────────┐  ┌───────────────────────────┐
│               Nick.app (SwiftUI)             │  │  NickFinderSync.appex     │
│          Menu Bar + Dashboard + Alerts       │◄─│  Finder context menu      │
├──────────────────────────────────────────────┤  │  App Group UserDefaults   │
│     NickLogging  (functional pipeline)       │  └───────────────────────────┘
│   KV / JSON / CEF  →  file / HTTP / stdout   │
├──────────────────────────────────────────────┤
│              Threat Correlator               │
│    Combines signals → CoreML threat score    │
├──────────┬──────────┬───────────┬────────────┤
│ Process  │ Persist- │ Network   │ File       │
│ Auditor  │ ence     │ Watchdog  │ System     │
│          │ Monitor  │ + Baseline│ Watcher    │
├──────────┴──────────┴───────────┴────────────┤
│              YARA Engine (libyara)            │
│          + Heuristic Analysis Layer           │
├──────────────────────────────────────────────┤
│          AI Behavioral Scorer (CoreML)        │
├──────────────────────────────────────────────┤
│           Privileged Helper (XPC)             │
│      SMAppService · Elevated Operations       │
└──────────────────────────────────────────────┘
```

### Project Structure

```
Nick/
├── Core/                        # Detection engine (pure Swift, no UI dependency)
│   ├── AVCapture/               # Camera and microphone activity monitoring
│   ├── BehavioralScorer/        # CoreML inference engine
│   ├── DeepScan/                # Full-system YARA deep scan driver
│   ├── Helper/                  # Privileged helper client interface
│   ├── Logging/                 # Functional alert logging pipeline (KV/JSON/CEF)
│   ├── Models/                  # Core-layer model types
│   ├── NetworkAnalyzer/         # Connection monitoring, tunnel detection, and baseline
│   ├── Notifications/           # NotificationManager
│   ├── PersistenceWatcher/      # LaunchAgent/Daemon/Login Item surveillance
│   ├── ProcessMonitor/          # Process auditing and anomaly detection
│   ├── Protocols/               # Shared monitor protocol definitions
│   ├── Services/                # macOS Services menu provider
│   ├── Settings/                # AppSettings
│   ├── SystemAudit/             # SIP, FileVault, Gatekeeper, firewall checks
│   ├── ThreatCorrelator/        # Multi-signal correlation, scoring, and suppression
│   ├── ThreatLog/               # Persistent threat log
│   ├── YARAEngine/              # C interop wrapper for libyara + FSEvents watcher
│   ├── SecurityEngine.swift     # Top-level observable state model
│   └── MonitorCoordinator.swift # Lifecycle orchestration for all monitors
│
├── App/                         # SwiftUI macOS application
│   ├── Dashboard/               # Overview, scanner, deep scan, network, and alert views
│   ├── Alerts/                  # Threat log export and history
│   ├── Settings/                # Settings view
│   ├── SystemAudit/             # System audit view
│   ├── Theme/                   # Design tokens (colors, typography, spacing, layout)
│   ├── MainWindowView.swift     # NavigationSplitView shell and sidebar
│   ├── NickApp.swift            # @main entry point
│   └── AppDelegate.swift        # NSStatusItem and engine bootstrap
│
├── NickHelper/                  # Privileged helper tool (XPC + SMAppService)
│
├── NickFinderSync/              # Finder Sync Extension — right-click "Scan with Nick"
│
├── Models/                      # Shared Swift model types
│   └── Training/                # CoreML training pipeline (Python)
│
├── Rules/                       # YARA rule sets
│   └── community/               # Community-contributed rules
│
└── Tests/
    ├── NickTests/               # Unit tests
    └── NickIntegrationTests/    # End-to-end detection tests
```

---

## Installation

### Requirements
- macOS 26 or later (required by the YARA static library)
- Apple Silicon or Intel Mac

### Download
Download the latest notarized `.dmg` from [Releases](https://github.com/EhsanAzish80/Nick/releases).

### Homebrew (coming soon)
```bash
brew install --cask nick-security
```

### Permissions
Nick requires the following permissions to function (each is requested individually with an explanation):

| Permission | Why |
|---|---|
| **Full Disk Access** | Monitor LaunchAgents, browser extensions, and system directories |
| **Network Monitoring** | Detect suspicious connections and tunnels |
| **Camera & Microphone** | Detect unauthorized access to media hardware |
| **Accessibility** | Detect UI-level process manipulation (optional) |
| **Notifications** | Alert you when threats are detected |

Nick never accesses your documents, photos, or personal files. Monitoring is limited to system directories, process tables, and network state.

---

## Building from Source

```bash
## Clone
git clone https://github.com/EhsanAzish80/Nick.git
cd Nick

## Open in Xcode (requires Xcode 26+)
open Nick.xcodeproj

## Build (includes Nick.app + NickFinderSync.appex + NickHelper)
xcodebuild -scheme Nick -configuration Release

## Run tests
xcodebuild test -scheme NickTests -destination "platform=macOS"

## Build unsigned (no signing team required)
xcodebuild -scheme Nick CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO
```

> The checked-in project uses the maintainer's signing team. Override with your own team in Xcode → Signing & Capabilities, or build unsigned using the command above.

> **Finder Sync Extension:** `NickFinderSync` requires both `Nick.app` and `NickFinderSync.appex` to share the App Group `group.com.ehsanazish.nick`. Add this entitlement in **Signing & Capabilities → App Groups** for both targets before building a signed release.

### Dependencies
Nick uses zero third-party Swift dependencies. External dependencies:

- **UI**: SwiftUI (Apple framework)
- **Persistence detection**: FSEvents, Foundation (Apple frameworks)
- **Network monitoring**: Network.framework, `sysctl` (Apple frameworks / POSIX)
- **Process auditing**: `proc_info`, `sysctl` (POSIX)
- **Scanning**: libyara 4.5.2 (vendored, BSD license)
- **AI scoring**: CoreML, Foundation Models (Apple frameworks)
- **Privileged helper**: SMAppService, XPC (Apple frameworks)
- **Automatic updates**: Sparkle 2 (Swift Package, MIT license)

---

## How Nick Compares

| Capability | Nick | Objective-See (6 tools) | Little Snitch | Intego | Norton |
|---|:---:|:---:|:---:|:---:|:---:|
| Process monitoring | ✅ | ✅ (BlockBlock + KnockKnock) | ❌ | ❌ | ✅ |
| Persistence detection | ✅ | ✅ (BlockBlock) | ❌ | ❌ | ✅ |
| Network monitoring | ✅ | ✅ (LuLu) | ✅ | ✅ (NetBarrier) | ✅ |
| Webcam/mic monitoring | ✅ | ✅ (OverSight) | ❌ | ❌ | ✅ |
| YARA scanning | ✅ | ❌ | ❌ | ✅ | ✅ |
| Behavioral AI scoring | ✅ | ❌ | ❌ | ❌ | ❌ |
| Correlated threat detection | ✅ | ❌ | ❌ | ❌ | ❌ |
| System hardening audit | ✅ | ❌ | ❌ | ❌ | ❌ |
| Log export (KV/JSON/CEF) | ✅ | ❌ | ❌ | ❌ | ❌ |
| SIEM webhook | ✅ | ❌ | ❌ | ❌ | ❌ |
| Open source | ✅ | ✅ | ❌ | ❌ | ❌ |
| No cloud dependency | ✅ | ✅ | ✅ | ❌ | ❌ |
| Single app | ✅ | ❌ (6 separate apps) | ✅ | ✅ | ✅ |
| Free | ✅ | ✅ | ❌ ($59) | ❌ ($40-70/yr) | ❌ ($40-80/yr) |

---

## Roadmap

### ✅ v1.0 — Public Release
### ✅ v1.1 — Detection Hardening

### ✅ v1.2 — AI & Reporting
- Functional logging pipeline (KV/JSON/CEF → file/webhook/stdout)
- Foundation Models explanations on all alert paths
- Network baseline anomaly detection
- Finder Sync Extension (right-click without user opt-in)
- Scheduled Deep Scan
- MDM configuration profile support
- Configurable alert suppression rules

### ✅ v3.0 — Endpoint Security & Real-Time Prevention *(current)*
- **Endpoint Security System Extension** — AUTH event interception; files blocked before execution
- **YARA engine in ES pipeline** — every cache-miss file evaluated against libyara 4.5.2 before allow/deny
- **15-rule behavioral correlator** — process genealogy + network correlation (added `parentChainRule`, `rawIpOutboundRule`)
- **LOLBin detector** — `curl`, `osascript`, `python3`, `launchctl`, `base64`, and more
- **Reverse shell detector** — shell process + outbound socket pattern matching
- **AV/Capture monitor** — unauthorized camera/mic session detection
- **Persistence watcher** — LaunchAgents/Daemons, Login Items, cron
- **Deep Scanner** — full-system YARA crawl, battery-aware
- **USB/external media auto-scan**
- **Network Inspector** — LAN host discovery and port scanning
- **Performance Engine** — 30+ disk cleanup rules (Xcode artifacts, caches, Docker, Steam, and more)
- **Security Score** redesigned (4 components, 0–100)
- **Export Security Report** — HTML report from System Audit toolbar
- **Automatic updates** via Sparkle 2 (`https://3nsofts.com/nick/appcast.xml`)
- Privileged helper migrated to `SMAppService` (modern API)

### 🔄 v3.1 — Behavioral Model & Community
- Homebrew cask distribution
- CoreML behavioral model activated (trained on opt-in telemetry from v3.0)
- Community YARA rule submission pipeline
- Alert aggregation view (group related alerts)

### 🔮 v4.0 — Network Prevention
- Network Extension (outbound connection blocking, DNS filtering)
- Scam Guardian — URL/phishing detection via network filter

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Ways to contribute:**
- 🐛 Report bugs and false positives
- 🧬 Submit YARA rules for macOS-specific threats
- 🧠 Improve the behavioral scoring model
- 📖 Improve documentation
- 🔍 Security audit and responsible disclosure (see [SECURITY.md](SECURITY.md))
- 🧪 Test on different Mac configurations

---

## Security

Nick is a security tool — we hold ourselves to a higher standard. If you discover a vulnerability in Nick itself, please follow our [responsible disclosure process](SECURITY.md). Do **not** open a public issue for security vulnerabilities.

---

## Uninstalling

1. Quit Nick from the menu bar icon → **Quit Nick**.
2. Open **Nick → Settings → Maintenance** and click **Remove Helper…** to unregister the privileged helper.
3. Drag `Nick.app` from `/Applications` to the Trash.
4. Remove preferences and data:
   ```bash
   defaults delete com.ehsanazish.nick
   rm -rf ~/Library/Application\ Support/Nick
   rm -f ~/Library/LaunchAgents/com.ehsanazish.nick.plist
   sudo rm -f /Library/LaunchDaemons/com.ehsanazish.nick.helper.plist
   sudo rm -f /Library/PrivilegedHelperTools/com.ehsanazish.nick.helper
   ```

---

## Philosophy

1. **No cloud, ever.** All scanning, analysis, and AI inference happens on your Mac. Your security data never leaves your machine.
2. **Zero third-party Swift dependencies.** Every dependency is an attack surface. Nick uses Apple frameworks and a single vendored C library (libyara).
3. **Transparency over trust.** You shouldn't trust any security tool blindly. Read the code. Audit the helper. Verify the signatures.
4. **Signals over alerts.** Individual events are noisy. Correlated behavioral scoring reduces false positives and surfaces real threats.
5. **Restraint over decoration.** Clean, native macOS interface. No scare tactics. No upsells. No dark patterns.

---

## License

Nick is licensed under the [GNU Affero General Public License v3.0](LICENSE).

This means you can freely use, modify, and distribute Nick. If you run a modified version as a network service, you must make your source code available. This ensures the security community always has access to the detection logic.

---

## Acknowledgments

Nick stands on the shoulders of:
- [Patrick Wardle](https://objective-see.org) and the Objective-See Foundation — for pioneering open-source macOS security
- [YARA](https://virustotal.github.io/yara/) — the pattern matching engine that powers malware research worldwide
- The macOS security research community — for continuously uncovering and documenting threats

---

<p align="center">
  Built by Ehsan Azish at <a href="https://3nsofts.com">3nsofts</a> · Crafted with Swift · Protected by the community
</p>
