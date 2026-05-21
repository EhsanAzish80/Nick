<p align="center">
  <img src="docs/assets/nick-banner.svg" alt="Nick" width="600">
</p>

<h3 align="center">Open-source macOS security suite with on-device AI threat scoring</h3>

<p align="center">
  One app. Six layers of protection. Zero cloud dependency. Read every line of code.
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#installation">Installation</a> •
  <a href="#building-from-source">Build</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#roadmap">Roadmap</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-macOS%2014%2B-000000?style=flat&logo=apple" alt="macOS 14+">
  <img src="https://img.shields.io/badge/swift-6.0-F05138?style=flat&logo=swift" alt="Swift 6.0">
  <img src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat" alt="AGPL-3.0">
  <img src="https://img.shields.io/github/stars/EhsanAzish80/Nick?style=flat" alt="Stars">
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

### 🔍 System Integrity Audit
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
- Embedded YARA engine (libyara) with curated macOS-specific rule set
- Community-contributed rules via pull requests
- Scheduled scans of critical directories
- Drag-and-drop scanning of any file or folder
- Heuristic analysis: entropy scoring, Mach-O header inspection, embedded URL/IP extraction

### 🧠 AI Behavioral Scoring (The Differentiator)
On-device CoreML model that correlates signals across all monitors:
- Individual signals are noisy. Correlated signals are actionable.
- `curl` downloading a binary to `/tmp` = medium risk
- That binary executing unsigned 2 seconds later = high risk
- That binary opening an outbound connection to a raw IP on port 443 = critical
- Natural-language alert explanations powered by on-device Foundation Models (macOS 26+)
- No data ever leaves your Mac

---

## Architecture

```
┌─────────────────────────────────────────────┐
│              Nick.app (SwiftUI)              │
│         Menu Bar + Dashboard + Alerts        │
├─────────────────────────────────────────────┤
│             Threat Correlator                │
│    Combines signals → CoreML threat score    │
├──────────┬──────────┬───────────┬───────────┤
│ Process  │ Persist- │ Network   │ File      │
│ Auditor  │ ence     │ Watchdog  │ System    │
│          │ Monitor  │           │ Watcher   │
├──────────┴──────────┴───────────┴───────────┤
│              YARA Engine (libyara)           │
│         + Heuristic Analysis Layer           │
├─────────────────────────────────────────────┤
│         AI Behavioral Scorer (CoreML)        │
├─────────────────────────────────────────────┤
│          Privileged Helper (XPC)             │
│     SMAppService · Elevated Operations       │
└─────────────────────────────────────────────┘
```

### Project Structure

```
Nick/
├── Core/                        # Detection engine (pure Swift, no UI dependency)
│   ├── ProcessMonitor/          # Process auditing and anomaly detection
│   ├── PersistenceWatcher/      # LaunchAgent/Daemon/Login Item surveillance
│   ├── NetworkAnalyzer/         # Connection monitoring and tunnel detection
│   ├── FileSystemWatcher/       # FSEvents-based directory monitoring
│   ├── YARAEngine/              # C interop wrapper for libyara
│   ├── SystemAudit/             # SIP, FileVault, Gatekeeper, firewall checks
│   ├── BehavioralScorer/        # CoreML inference engine
│   └── ThreatCorrelator/        # Multi-signal correlation and scoring
│
├── App/                         # SwiftUI macOS application
│   ├── Dashboard/               # Main security overview
│   ├── Alerts/                  # Threat notifications and history
│   ├── Scanner/                 # On-demand YARA scanning UI
│   ├── SystemAudit/             # Hardening recommendations
│   ├── NetworkView/             # Live connection viewer
│   └── Settings/                # Configuration and preferences
│
├── Helper/                      # Privileged helper tool
│   └── PrivilegedOperations/    # Elevated access via XPC + SMAppService
│
├── Models/                      # Machine learning
│   ├── ThreatScorer.mlmodel     # CoreML behavioral scoring model
│   └── Training/                # Python training scripts and datasets
│
├── Rules/                       # YARA rule sets
│   ├── stealers/                # Credential and data theft
│   ├── backdoors/               # Remote access and persistence
│   ├── adware/                  # Potentially unwanted programs
│   ├── ransomware/              # Encryption-based threats
│   └── community/               # Community-contributed rules
│
└── Tests/
    ├── UnitTests/               # Core engine tests
    └── IntegrationTests/        # End-to-end detection tests
```

---

## Installation

### Requirements
- macOS 14 Sonoma or later
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
| **Accessibility** | Detect UI-level process manipulation (optional) |
| **Notifications** | Alert you when threats are detected |

Nick never accesses your documents, photos, or personal files. Monitoring is limited to system directories, process tables, and network state.

---

## Building from Source

```bash
# Clone
git clone https://github.com/EhsanAzish80/Nick.git
cd Nick

# Open in Xcode
open Nick.xcodeproj

# Build (requires Xcode 16+)
xcodebuild -scheme Nick -configuration Release

# Run tests
xcodebuild test -scheme NickTests
```

### Dependencies
Nick uses zero third-party Swift dependencies. The only external dependency is `libyara` (C library, vendored).

- **UI**: SwiftUI (Apple framework)
- **Persistence detection**: FSEvents, Foundation (Apple frameworks)
- **Network monitoring**: Network.framework, `sysctl` (Apple frameworks / POSIX)
- **Process auditing**: `proc_info`, `sysctl` (POSIX)
- **Scanning**: libyara (vendored, BSD license)
- **AI scoring**: CoreML, Foundation Models (Apple frameworks)
- **Privileged helper**: SMAppService, XPC (Apple frameworks)

---

## How Nick Compares

| Capability | Nick | Objective-See (6 tools) | Little Snitch | Intego | Norton |
|---|:---:|:---:|:---:|:---:|:---:|
| Process monitoring | ✅ | ✅ (BlockBlock + KnockKnock) | ❌ | ❌ | ✅ |
| Persistence detection | ✅ | ✅ (BlockBlock) | ❌ | ❌ | ✅ |
| Network monitoring | ✅ | ✅ (LuLu) | ✅ | ✅ (NetBarrier) | ✅ |
| Webcam/mic monitoring | 🔜 | ✅ (OverSight) | ❌ | ❌ | ✅ |
| YARA scanning | ✅ | ❌ | ❌ | ✅ | ✅ |
| Behavioral AI scoring | ✅ | ❌ | ❌ | ❌ | ❌ |
| Correlated threat detection | ✅ | ❌ | ❌ | ❌ | ❌ |
| System hardening audit | ✅ | ❌ | ❌ | ❌ | ❌ |
| Open source | ✅ | ✅ | ❌ | ❌ | ❌ |
| No cloud dependency | ✅ | ✅ | ✅ | ❌ | ❌ |
| Single app | ✅ | ❌ (6 separate apps) | ✅ | ✅ | ✅ |
| Free | ✅ | ✅ | ❌ ($59) | ❌ ($40-70/yr) | ❌ ($40-80/yr) |

---

## Roadmap

### v0.1 — Foundation (In Progress)
- [ ] System integrity audit (SIP, FileVault, Gatekeeper, firewall, XProtect)
- [ ] LaunchAgent/Daemon monitoring with change detection
- [ ] Process auditor (unsigned binaries, suspicious locations, parent-child chains)
- [ ] Network connection viewer with process mapping
- [ ] SwiftUI menu bar app with dashboard

### v0.5 — Active Detection
- [ ] FSEvents watcher on critical directories
- [ ] YARA engine integration with curated rule set
- [ ] On-demand file/directory scanner
- [ ] Heuristic analysis (entropy, code signing, Mach-O inspection)
- [ ] Real-time notification system
- [ ] Privileged helper for elevated operations

### v0.9 — AI Behavioral Scoring
- [ ] Threat correlation engine (multi-signal scoring)
- [ ] CoreML behavioral scoring model
- [ ] Foundation Models alert explanations (macOS 26+)
- [ ] Real-time behavioral monitoring
- [ ] Threat log with forensic detail

### v1.0 — Public Release
- [ ] Third-party security audit of privileged helper and detection engine
- [ ] False positive tuning across diverse Mac configurations
- [ ] Performance optimization (< 1% CPU, < 50MB RAM)
- [ ] Homebrew cask distribution
- [ ] Comprehensive documentation

### Future
- [ ] Webcam/microphone monitoring (OverSight equivalent)
- [ ] DNS-over-HTTPS tunnel detection
- [ ] Community rule marketplace
- [ ] Automated incident response actions
- [ ] Enterprise deployment support

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
  Built by <a href="https://3nsofts.com">3nsofts</a> · Crafted with Swift · Protected by the community
</p>
