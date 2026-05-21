# Nick Architecture

This document describes Nick's internal architecture, detection methodology, and security model. It's intended for contributors, security auditors, and anyone who wants to understand how Nick works before trusting it on their Mac.

## Design Principles

1. **Defense in depth through correlation.** Any single signal (an unsigned binary, an outbound connection, a new LaunchAgent) could be benign. Nick's value is in correlating signals across monitors to surface genuinely suspicious behavior while minimizing false positives.

2. **Minimal attack surface.** Nick uses zero third-party Swift dependencies. The privileged helper exposes the smallest possible XPC API. The app requests only the permissions it needs.

3. **Offline by default.** Nick makes no network connections unless the user explicitly enables rule update checks. All scanning, analysis, and AI inference runs locally on the Mac.

4. **Separation of concerns.** The detection engine (`Core/`) has no UI dependency and can be tested, audited, and embedded independently. The UI (`App/`) is a thin layer over the engine. The privileged helper (`Helper/`) is isolated behind XPC.

---

## Component Overview

### Core Detection Engine

The engine consists of independent monitors that each observe a specific attack surface. Each monitor emits `ThreatSignal` events to the `ThreatCorrelator`.

```
ThreatSignal {
    source: MonitorType          // .process, .persistence, .network, .filesystem
    severity: SignalSeverity     // .info, .low, .medium, .high, .critical
    timestamp: Date
    processInfo: ProcessInfo?    // PID, path, code signing status, parent
    networkInfo: NetworkInfo?    // remote IP, port, protocol, domain
    fileInfo: FileInfo?          // path, hash, entropy, signing status
    description: String          // Human-readable signal description
    rawData: [String: Any]       // Full context for correlation
}
```

#### ProcessMonitor
**What it watches:** Running processes via `sysctl` / `proc_info`.

**Detection logic:**
- Flags processes executing from `/tmp`, `/var/tmp`, or hidden directories (path contains `/\.`)
- Flags unsigned or ad-hoc signed binaries (checks code signing via `SecStaticCode`)
- Detects shell processes (`bash`, `zsh`, `sh`, `python`, `ruby`, `perl`) with active network connections (cross-references with NetworkAnalyzer)
- Identifies suspicious parent-child chains (e.g., `Safari` → `bash` → `curl`)
- Monitors LOLBin usage patterns: `curl` piping to `sh`, `osascript` with encoded payloads, `openssl s_client` connections

**Polling interval:** 5 seconds (configurable).

#### PersistenceWatcher
**What it watches:** Known macOS persistence locations via FSEvents.

**Monitored paths:**
- `/Library/LaunchDaemons/`
- `/Library/LaunchAgents/`
- `~/Library/LaunchAgents/`
- `/System/Library/LaunchDaemons/` (read-only check, SIP-protected)
- Login Items (via `SMAppService` API)
- `/etc/crontab` and user crontabs
- `/etc/periodic/` (daily, weekly, monthly)
- `/Library/SystemExtensions/`
- Browser extension directories (Safari, Chrome, Firefox, Arc)

**Detection logic:**
- Emits a `.high` signal for any new file in a LaunchAgent/Daemon directory
- Parses plist files to extract the executable path and validates its code signature
- Compares current persistence state against a baseline snapshot (created on first run)
- Detects modification of existing persistence plists (not just creation)

#### NetworkAnalyzer
**What it watches:** Active network connections, listening ports, DNS queries.

**Data sources:**
- `NWPathMonitor` for connectivity state
- `getifaddrs` / `sysctl` for active connections (equivalent to `netstat`)
- `lsof -i` output parsing for process-to-connection mapping
- DNS query monitoring via `dns-sd` or `/var/log/` system logs

**Detection logic:**
- Flags unexpected listening ports (ports not associated with known macOS services)
- Detects reverse shells: shell process (`bash`, `zsh`) with outbound TCP connection
- Identifies SSH tunnels by inspecting `ssh` process arguments for `-L`, `-R`, `-D` flags
- Flags connections from shell processes to raw IPs (no DNS resolution = suspicious)
- Monitors for connections to known malicious domains/IPs (loaded from Rules/indicators/)
- Detects unexpected DNS-over-HTTPS traffic to non-standard resolvers

#### FileSystemWatcher
**What it watches:** File creation and modification in critical directories via FSEvents.

**Monitored directories:**
- `~/Downloads/`
- `/tmp/` and `/var/tmp/`
- `/Applications/`
- All persistence directories (shared with PersistenceWatcher)
- Browser extension directories

**Detection logic:**
- New executable files in `/tmp` → `.medium` signal
- New `.app`, `.pkg`, `.dmg` in Downloads → `.info` signal (triggers YARA scan)
- Modification of any file in persistence directories → `.high` signal
- Rapid file creation patterns (many files in short time) → potential dropper behavior

#### YARAEngine
**What it does:** Pattern-based file scanning using the YARA library.

**Implementation:**
- `libyara` (C library) wrapped in a Swift interface via C interop
- Rules compiled at app launch and cached
- Supports on-demand scanning (user-initiated) and triggered scanning (from FileSystemWatcher events)
- Ships with curated rule sets organized by threat type
- Community rules loaded from `Rules/community/` directory

**Scanning modes:**
- **Quick scan**: Critical directories only (~30 seconds)
- **Full scan**: All user-accessible directories (varies by disk size)
- **Targeted scan**: Single file or directory (user-initiated)
- **Real-time scan**: Triggered by FileSystemWatcher for new files in monitored directories

#### SystemAudit
**What it checks:** macOS security configuration.

| Check | Method | Expected State |
|-------|--------|----------------|
| SIP | `csrutil status` via Process | Enabled |
| FileVault | `fdesetup status` via Process | On |
| Gatekeeper | `spctl --status` via Process | Assessments enabled |
| Firewall | `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate` | Enabled |
| Stealth mode | `socketfilterfw --getstealthmode` | Enabled (recommended) |
| XProtect | Check plist version at `/Library/Apple/System/Library/CoreServices/XProtect.bundle` | Up to date |
| Automatic updates | `defaults read /Library/Preferences/com.apple.SoftwareUpdate` | Enabled |
| Remote Login | `systemsetup -getremotelogin` (requires helper) | Off (unless intentional) |
| Sharing services | Various `launchctl` checks | Minimal |

---

### ThreatCorrelator

The correlator is the central intelligence component. It receives `ThreatSignal` events from all monitors and scores them using both rule-based logic and the CoreML behavioral model.

**Correlation windows:** Signals are correlated within a 30-second sliding window by default.

**Correlation rules (examples):**
```
IF ProcessMonitor.unsigned_binary_executing
   AND FileSystemWatcher.new_file_in_tmp (same path, within 10s)
   AND NetworkAnalyzer.outbound_connection (same PID, within 30s)
THEN → score: 0.92, label: "Dropper behavior detected"

IF PersistenceWatcher.new_launchagent
   AND ProcessMonitor.parent_is_installer_or_browser
   AND YARAEngine.no_match (file is clean by signatures)
THEN → score: 0.65, label: "Unknown persistence mechanism from web download"

IF NetworkAnalyzer.shell_with_outbound_connection
   AND ProcessMonitor.parent_not_terminal
THEN → score: 0.95, label: "Possible reverse shell"
```

**CoreML scoring:**
The behavioral model takes a feature vector of ~40 signals (binary flags and numeric values) and outputs a threat probability between 0.0 and 1.0. The model is trained on labeled behavioral data from known-good macOS activity and known-bad malware behavior.

Feature categories:
- Process attributes (signing status, location, parent chain depth, age)
- Network attributes (connection count, destination type, port, protocol)
- File system attributes (file entropy, location, creation recency)
- Temporal attributes (time since process start, time between events)

**Alert thresholds:**
- `< 0.3` → Logged, no notification
- `0.3 - 0.6` → Low priority notification
- `0.6 - 0.8` → Medium priority notification with explanation
- `> 0.8` → High priority notification with recommended action

---

### Privileged Helper

The helper runs as a separate process with elevated privileges, communicating with the main app via XPC.

**XPC Protocol (minimal surface):**
```swift
@objc protocol NickHelperProtocol {
    func checkFirewallRules(reply: @escaping ([String: Any]) -> Void)
    func checkRemoteLoginStatus(reply: @escaping (Bool) -> Void)
    func readProtectedPlist(atPath: String, reply: @escaping (Data?) -> Void)
    func getSystemIntegrityStatus(reply: @escaping ([String: Any]) -> Void)
}
```

**Security measures:**
- Code signing requirement on both ends of the XPC connection
- The helper validates the calling app's code signature before responding
- No write operations exposed — the helper is read-only
- No shell execution — all checks use Foundation APIs or direct syscalls
- Installed and managed via `SMAppService` (modern replacement for `SMJobBless`)

---

### App Layer (SwiftUI)

The app is a thin presentation layer over the Core engine.

**Main views:**
- **Dashboard**: System health score, active monitors status, recent alerts summary
- **Alerts**: Chronological threat log with severity, description, affected process/file, and recommended action
- **Scanner**: Drag-and-drop YARA scanning with results display
- **System Audit**: Security configuration checklist with fix recommendations
- **Network**: Live connection viewer with process mapping
- **Settings**: Monitor toggles, scan scheduling, notification preferences

**Menu bar presence:**
- Status icon: green (all clear), yellow (low-priority alerts), red (high-priority alert)
- Click to open dashboard or show recent alerts
- Lightweight — the menu bar extra runs even when the main window is closed

---

## Data Flow

```
                    User's Mac
                        │
    ┌───────────────────┼───────────────────┐
    │                   │                   │
    ▼                   ▼                   ▼
ProcessMonitor   NetworkAnalyzer   FileSystemWatcher
    │                   │                   │
    │                   │                   │
    └───────┬───────────┴───────────┬───────┘
            │                       │
            ▼                       ▼
    PersistenceWatcher        YARAEngine
            │                       │
            └───────────┬───────────┘
                        │
                        ▼
               ThreatCorrelator
                   │        │
                   │        ▼
                   │   BehavioralScorer
                   │   (CoreML inference)
                   │        │
                   ▼        ▼
              Alert Decision
                   │
                   ▼
            SwiftUI Dashboard
            + Notification
```

All data stays on-device. The only persistent storage is:
- Baseline snapshots (for diff detection)
- Alert history (SQLite via SwiftData)
- User preferences
- YARA rule cache

---

## Threat Model

### What Nick Protects Against
- Post-exploitation persistence (attacker already has initial access, tries to maintain it)
- Info-stealer malware (credential theft, keychain access, browser data exfiltration)
- Living-off-the-land attacks (abuse of built-in macOS tools)
- Adware and PUAs (browser hijackers, search engine changers)
- Reverse shells and unauthorized remote access
- Degradation of security posture (SIP disabled, firewall turned off)

### What Nick Does NOT Protect Against
- Kernel-level rootkits (would require Endpoint Security entitlement from Apple)
- Zero-day exploits in macOS itself (no userspace tool can fully prevent these)
- Physical access attacks
- Social engineering (Nick can't stop you from entering your password into a phishing site)
- Attacks that occur before Nick is running

### Nick's Own Security
- The privileged helper is the highest-risk component. It's intentionally minimal and read-only.
- XPC connections are validated with code signing requirements on both ends.
- The app runs with hardened runtime and library validation.
- YARA rule files are validated before loading (malformed rules can't crash the engine).
- The CoreML model is a read-only inference artifact — it can't be poisoned at runtime.

---

## Future Architecture Considerations

- **Endpoint Security framework**: If Apple grants the entitlement, ES provides richer process and file event data than `sysctl`/FSEvents. This would be a major detection improvement but requires Apple approval.
- **Network Extension**: Would enable true packet-level filtering. Currently, Nick monitors connections but can't block them. A Network Extension would add blocking capability.
- **Distributed rule updates**: A signed, versioned rule distribution mechanism for YARA updates and threat indicators. Would require the app to make network connections (opt-in only).

---

This architecture is a living document. Feedback, criticism, and security review are welcome — open an issue or see [CONTRIBUTING.md](CONTRIBUTING.md).
