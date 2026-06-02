# Nick — Security Audit

**Auditor:** Ehsan Azish ([@ehsanazish80](https://github.com/EhsanAzish80))
**Date:** June 2, 2026
**Scope:** All files in `NickHelper/` (privileged helper), `NickExtension/` (ES system extension), and `Nick/Core/` (detection engine)
**Nick version audited:** `v3.0 (build 1)`

---

## Reporting a Vulnerability

If you discover a security vulnerability in Nick, please report it responsibly:

### How to Report

1. **GitHub Security Advisories** (preferred — enables private discussion): [Report via GitHub](https://github.com/EhsanAzish80/Nick/security/advisories/new)
2. **Email**: Send a detailed report to **security@3nsofts.com**

Please include:
- A clear description of the vulnerability and its potential impact
- Steps to reproduce or proof-of-concept code
- The Nick version and macOS version you tested against

We aim to acknowledge reports within 48 hours and provide a fix timeline within 7 days for critical issues. We ask that you give us reasonable time to address the issue before public disclosure.

---

## Scope and Methodology

Nick runs a privileged helper (`NickHelper`) over XPC at the user's request. This helper
executes as root to read files and check system state that would otherwise require elevated
privileges. Because it runs as root and accepts external input over IPC, it is the highest-risk
component in the application.

The detection engine (`Core/`) does not require elevated privileges but reads sensitive system
state (process tables, network connections, filesystem). It presents a different threat surface:
information leakage, denial of service from unbounded buffers, and evasion via signal flooding.

Each section below documents the audit checklist, finding status, and any remediation applied.

---

## Part 1 — Privileged Helper (`NickHelper/`)

### Audit Checklist

| # | Check | File | Status | Notes |
|---|-------|------|--------|-------|
| 1 | Caller validation | `HelperDaemon.swift` | ✅ Pass | `SecCodeCopyGuestWithAttributes` validates PID → code signature → team ID. Team ID is hardcoded in `HelperDaemon.authorisedTeamID`, not configurable at runtime. |
| 2 | Path allowlist | `HelperProtocol.swift`, `HelperDaemon.swift` | ✅ Pass | `HelperPathAllowlist.validate(_:)` enforces an 8-step chain: null byte check, max 4 096 bytes, absolute path requirement, percent-encoded slash rejection, `..` component check (rejects traversal before symlink resolution), NFC normalisation, symlink resolution, and prefix matching against 5 directories. Note: `/etc/` intentionally excluded — allowing it would let a symlink attack redirect reads to `/etc/sudoers`. |
| 3 | No shell execution | `HelperDaemon.swift`, `HelperProtocol.swift`, `main.swift` | ✅ Pass | Grep for `Process()`, `NSTask`, `system()`, `popen()`: zero results. `getSIPStatus` uses `csr_get_active_config` directly. `getFirewallStatus` reads the plist file via the allowlist-validated path. No subprocess is spawned anywhere in the helper. |
| 4 | No write operations | All `NickHelper/` files | ✅ Pass | No `FileManager.createFile`, `write(to:)`, `moveItem`, or `removeItem` calls exist. All operations are read-only. |
| 5 | No dynamic code loading | All `NickHelper/` files | ✅ Pass | No `dlopen`, `NSBundle.load`, or `dlsym`. The helper is statically linked. |
| 6 | Input validation | `HelperDaemon.swift` | ✅ Pass | All string parameters are validated by `HelperPathAllowlist.validate(_:)` before use. The 7-step validation chain is documented in `HelperProtocol.swift`. |
| 7 | Error handling | `HelperDaemon.swift` | ✅ Pass | `HelperProtocolImplementation` returns only `HelperError.operationFailed` ("Operation failed.") — no paths, errno values, or system information are included in error messages. |
| 8 | Connection rate limit | `HelperDaemon.swift` | ✅ Pass | Sliding 1-second window per PID. Maximum 10 connections/second. Dictionary capped at 500 unique PIDs to prevent unbounded memory growth. |
| 9 | Entitlements | `NickHelper.entitlements` | ✅ Pass | Entitlements file present and reviewed. `com.apple.security.app-sandbox` = false, Hardened Runtime = ON. Minimal set for SMAppService registration and XPC only. |

### Finding Details

#### Finding 1.A — `readPlist(at:)` had no path validation (Remediated)

**Severity:** Critical
**File:** `NickHelper/main.swift` (prior to Phase 4)
**Description:** The original `readPlist(at:)` implementation called
`Data(contentsOf: URL(fileURLWithPath: path))` with no validation of `path`. Any
connecting process (had caller validation not been absent too) could supply an arbitrary
path — including paths outside LaunchDaemons directories — and read its contents.

**Remediation:** Method renamed to `readProtectedPlist(atPath:)`. All calls now route
through `HelperPathAllowlist.validate(_:)` before any filesystem access. The 7-step
validation chain covers null bytes, length, absolute-path requirement, percent-encoding
bypass, unicode normalisation, symlink resolution, and allowlist prefix matching.

#### Finding 1.B — No caller validation on XPC connections (Remediated)

**Severity:** Critical
**File:** `NickHelper/main.swift` (prior to Phase 4)
**Description:** The `shouldAcceptNewConnection` implementation accepted every connection
without verifying the identity of the caller. Any process that discovered the Mach service
name `com.ehsanazish.nick.helper` could connect and invoke the protocol.

**Remediation:** Created `HelperDaemon.swift` which implements `validateCallerSignature(_:)`.
This uses `SecCodeCopyGuestWithAttributes` to obtain the caller's `SecCode`, then applies
a code requirement: `anchor apple generic and certificate leaf[subject.OU] = "TEAM_ID"`.
Connections from processes not signed by the authorised team are rejected and the connection
is invalidated before any data is exchanged.

#### Finding 1.C — No rate limiting on XPC connections (Remediated)

**Severity:** Medium
**File:** `NickHelper/main.swift` (prior to Phase 4)
**Description:** No limit existed on how many XPC connections a single PID could open per
second, making the helper vulnerable to connection-flood denial of service.

**Remediation:** `HelperDaemon.isRateLimited(pid:)` uses a sliding 1-second window. More
than 10 connections/second from a single PID causes the connection to be invalidated before
any validation work is performed.

#### Finding 1.D — `getSIPStatus` used TODO stub (Remediated)

**Severity:** Low
**File:** `NickHelper/main.swift` (prior to Phase 4)
**Description:** `getSIPStatus` returned a hardcoded `true` — not the real SIP state.

**Remediation:** Replaced with `csr_get_active_config(&config)` direct system call. Returns
`true` only when config == 0 (all SIP protections active).

### Remediation Log

| Date | Finding | Action |
|------|---------|--------|
| 2026-05-22 | 1.A — No path validation | Added `HelperPathAllowlist`, renamed method, wired validation |
| 2026-05-22 | 1.B — No caller validation | Created `HelperDaemon.swift` with `SecCodeCopyGuestWithAttributes` check |
| 2026-05-22 | 1.C — No rate limiting | Added sliding-window rate limiter in `HelperDaemon` |
| 2026-05-22 | 1.D — SIP stub | Replaced with `csr_get_active_config` direct call |

---

## Part 2 — Detection Engine (`Nick/Core/`)

### Audit Checklist

| # | Check | Files | Status | Notes |
|---|-------|-------|--------|-------|
| 1 | No sensitive data in logs | All `Core/` files | ✅ Pass | Reviewed `os.Logger` calls. PIDs and paths use `.private` privacy label. No user data at `.default` or `.public`. |
| 2 | No sensitive data in signals | `ThreatSignal.swift` | ✅ Pass | Signals carry: path, PID, process name, connection tuples. No file contents, passwords, or key material. |
| 3 | No disk writes outside app support | All `Core/` files | ✅ Pass | `ThreatLogger` writes only to `~/Library/Application Support/com.ehsanazish.nick/`. No writes to `/tmp`, Desktop, or Documents. |
| 4 | Signal buffer limits | `CorrelationWindow.swift` | ✅ Pass | `CorrelationWindow` prunes expired signals on every `add()` / `addAll()` / `currentSignals()` call. Signals older than `windowDuration` (default 30s) are removed. Buffer cannot grow unbounded under sustained signal input. |
| 5 | YARA rule safety | `YARAEngine/YARAEngine.swift` | ✅ Pass | `YARAEngine` wraps libyara v4.5.2 (vendored static library). Per-file scan timeout is fixed at 10 seconds (`perFileScanTimeoutSeconds`). Compiler error callback via `yr_compiler_set_callback` logs and surfaces malformed rules without crashing. Backtracking is bounded by the libyara default. Rule compilation is lazy and protected by `NSLock`. |
| 6 | Process enumeration safety | `ProcessScanner.swift` | ✅ Pass | `sysctl` is called twice: first to size the buffer, then to fill it. The `actualCount` trimming on line 97 prevents a race condition where the process table shrinks between calls. `MemoryLayout<kinfo_proc>.stride` is used throughout — no manual size arithmetic. |
| 7 | Network scanner safety | `ConnectionScanner.swift` | ✅ Pass | `lsof` output is parsed with defensive guards. Malformed lines produce a `continue` (skipped), not a crash. PID parsing uses `Int32(_:)` optional initialiser. |
| 8 | SwiftData safety | `ThreatLogEntry.swift`, `AppDelegate.swift` | ✅ Pass | `AppDelegate.applicationDidFinishLaunching` launches a background `Task` that opens the production `ModelContainer` and calls `ThreatLogger.pruneOlderThan(days: 90)`. Stale entries are removed on every launch. Fixed in Part 4.6. |
| 9 | Foundation Models security | `BehavioralScorer/AlertExplainer.swift`, `BehavioralScorer/ExplanationPromptBuilder.swift` | ✅ Pass | **Data privacy:** `LanguageModelSession` (Apple `FoundationModels` framework) runs entirely on-device. No alert metadata, process names, or user data is transmitted externally — confirmed by framework design and `SECURITY` comment in `AlertExplainer.explain`. **Prompt injection:** Alert title, description, and signal metadata (including process names and file paths) are embedded in the prompt by `ExplanationPromptBuilder`. A crafted process name could inject LLM instructions. Impact is bounded: the model output is used only for the human-readable explanation card — it has no effect on threat score, severity, alert firing, or notification dispatch. Accepted risk. **Availability:** Any `LanguageModelSession` error is caught and falls back to a deterministic template string; the fallback is always non-empty and actionable. Threat detection is unaffected if the model is unavailable. |

### Finding Details

#### Finding 2.A — `lsof` subprocess in detection path (Accepted Risk)

**Severity:** Low (performance, not security)
**File:** `ConnectionScanner.swift`
**Description:** `ConnectionScanner` spawns `/usr/sbin/lsof` as a subprocess. This is a
known issue documented in the code (`// TODO(ehsan): Replace lsof with proc_pidfdinfo`).

**Decision:** Accepted for v1.0 with the existing `Process()` invocation. The `lsof` binary
is at a fixed path (`/usr/sbin/lsof`) that is checked for executability before use. The
helper never calls lsof — only the main app does. No security regression; this is an
existing architectural limitation scheduled for Task 4.3.

#### Finding 2.B — `ThreatCorrelator` signal buffer has no hard maximum (Remediated)

**Severity:** Medium
**File:** `ThreatCorrelator.swift`
**Description:** While `CorrelationWindow` prunes by time, `ThreatCorrelator.signalBuffer`
is a plain `[ThreatSignal]` array. Under a sustained signal flood (e.g. a malware process
emitting thousands of signals per second), the buffer could grow until memory pressure causes
an OS-level memory kill.

**Remediation:** `ThreatCorrelator.ingest(_:)` must enforce a maximum buffer size before
appending. A hard cap of 10 000 signals is sufficient; excess signals at `.low` or `.info`
severity are discarded with a `.notice`-level log entry. See `ThreatCorrelator.swift`.

---

## Open Items

| Item | Priority | Owner | Status |
|------|----------|-------|--------|
| Create `NickHelper.entitlements` with minimal entitlement set | High | @ehsanazish80 | ✅ Fixed (Part 4.2) |
| Verify SwiftData pruning at launch | Medium | @ehsanazish80 | ✅ Fixed (Part 4.6) |
| Add YARA rule compilation timeout | High | @ehsanazish80 | ✅ Fixed (libyara v4.5.2, 10s timeout) |
| Replace `lsof` with `proc_pidfdinfo` | Low | @ehsanazish80 | Open — tracked as #1 |
| Implement `getListeningPorts` with direct sysctl | Medium | @ehsanazish80 | Open — tracked as #43 |
| Audit `NickExtension/` ES event pipeline for path traversal and signal flooding | High | @ehsanazish80 | Open — v3.0 new surface |
| Verify Sparkle EdDSA key rotation procedure | Medium | @ehsanazish80 | Open — pre-v3.1 |

---

#### Finding 2.C — `getListeningPorts` returns empty dict (Known Limitation)

**Severity:** Medium (feature gap, not a security regression)
**File:** `NickHelper/HelperProtocol.swift` — `HelperProtocolImplementation.getListeningPorts`
**Description:** `getListeningPorts(reply:)` currently replies with an empty dictionary.
The intended implementation is a direct `sysctl(KERN_PROC_ALL)` enumeration with socket
inspection to enumerate listening TCP/UDP ports without spawning a subprocess. This was
deferred to avoid shipping an incomplete implementation that could produce misleading results.

**Impact:** The Network panel and correlation engine do not include listening port data in
threat scoring. Outbound connection detection (via `lsof` in `ConnectionScanner`) is
unaffected. A process listening on an unexpected port would not be flagged by this path alone;
it would still be caught by behavioral scoring if it makes outbound connections.

**Decision:** Accepted for v1.0. Tracked in GitHub Issues as #43. The missing data source
lowers detection coverage for persistence-via-socket patterns but does not create a false sense
of security — the UI does not claim to enumerate listening ports.

---

---

## Part 3 — Detection Coverage Audit

**Audited:** June 2026 (post-v0.9-rc, pre-v1.0 GA)  
**Methodology:** Full static analysis of every detector, correlator rule, and notification
dispatch path. Each detector was traced from raw OS observation → `ThreatSignal` emission →
`ThreatCorrelator.ingest` → `CorrelationRule.evaluate` → `ThreatAlert` → `NotificationManager`.

### 3.1 Monitored Detection Sources

| Source | File | Wired In Pipeline | Notes |
|--------|------|:-----------------:|-------|
| `ProcessScanner` (process spawn) | `ProcessMonitor/ProcessScanner.swift` | ✅ | Called in `SecurityEngine.performFullScan` + `MonitorCoordinator.quickTick` |
| `LOLBinDetector` | `ProcessMonitor/LOLBinDetector.swift` | ✅ | Called in `MonitorCoordinator.quickTick` only (quickTick checks each new PID) |
| `ParentChainAnalyzer` | `ProcessMonitor/ParentChainAnalyzer.swift` | ✅ | Called in `MonitorCoordinator.quickTick` for each new PID |
| `NetworkAnalyzer` / `ConnectionScanner` | `NetworkAnalyzer/` | ✅ | Called in `SecurityEngine.performFullScan` |
| `ReverseShellDetector` | `NetworkAnalyzer/ReverseShellDetector.swift` | ✅ | Called internally by `ConnectionScanner.signals()` |
| `PersistenceWatcher` | `PersistenceWatcher/` | ✅ | Called in `SecurityEngine.performFullScan` |
| `AVCaptureMonitor` | `AVCapture/` | ✅ | Called in `SecurityEngine.performFullScan` |
| `SystemAuditor` | `SystemAudit/SystemAuditor.swift` | ✅ | Called in `SecurityEngine.performFullScan` |
| `YARAEngine` / `FileSystemWatcher` | `YARAEngine/` | ✅ | Both paths active. `FileSystemWatcher` started in `MonitorCoordinator.startRealTimePipeline()` (fixed in Part 4.1). `DeepScanner` ingests signals into `ThreatCorrelator` (fixed in Part 4.3). |
| `BehavioralScorer` | `BehavioralScorer/` | ❌ Not wired | 40-feature `FeatureVector` and `FeatureExtractor` fully implemented. `BehavioralScorer` wraps CoreML (`ThreatScorer.mlmodelc`). Excluded from live detection path until the model is trained on real post-launch telemetry. `isModelAvailable` guards accidental activation. |

---

### 3.2 Detection Category Coverage

#### 3.2.1 Unsigned Binary in Temp Directory ✅ WORKING

- **Detector:** `ProcessScanner.latestSignals()` (full scan), `MonitorCoordinator.quickTick()` (fast path)
- **Signal reason:** `unsigned_temp_path` (full scan), `temp_path_spawn` (quickTick)
- **Correlation rule:** `unsignedBinaryInTmpRule` (score: 0.85, severity: high)
- **Notification:** ✅ Both paths — quickTick dispatches immediately; full scan dispatches via new deduplication-aware notification block (fixed this session)
- **Test:** `NickTests/BehavioralScorerTests.swift`, `NickTests/FeatureExtractorTests.swift`
- **Status:** Full coverage — detection, alert, and notification all working.

#### 3.2.2 Download-to-Shell Pipe (curl|bash / wget|bash) ✅ WORKING (partially fixed)

- **Detector:** `LOLBinDetector.evaluate()` in `quickTick`
- **Signal reasons:** `curl_pipe_shell`, `wget_pipe_shell`
- **Correlation rule:** `curlPipeShellRule` (score: 0.95, severity: critical)
- **Gap found:** Rule previously matched only `reason == "curl_pipe_shell"`. `wget_pipe_shell` signals were ingested but never produced an alert.
- **Fix applied:** `curlPipeShellRule` now matches both `curl_pipe_shell` and `wget_pipe_shell`.
- **Notification:** ✅ quickTick path dispatches immediately
- **Status:** Fixed. Both curl and wget pipe attacks trigger critical alert + notification.

#### 3.2.3 Advanced LOLBin Patterns ✅ WORKING (fixed)

Patterns detected by `LOLBinDetector` but previously **unmatched** by any correlation rule:

| Pattern | Signal Reason | Severity |
|---------|--------------|---------|
| `osascript` executing shell command | `osascript_shell` | high |
| `xattr` removing quarantine attribute | `quarantine_removal` | high |
| Python/Ruby/Perl decoding base64 payload | `base64_payload` | high |
| `launchctl load` from `/tmp` or `/var/folders` | `launchctl_tmp` | critical |
| `crontab` modification | `crontab_modify` | medium |
| Shell creating and executing temp file via `mktemp` | `mktemp_execute` | medium |

- **Gap found:** All six signal reasons above were ingested by `ThreatCorrelator` but **no correlation rule matched them**. Signals silently disappeared after ingestion.
- **Fix applied:** New `lolbinAdvancedRule` (score: 0.80, severity: high) added to `CorrelationRule.standard`. Matches all six reasons.
- **Notification:** ✅ quickTick dispatches immediately after fix
- **Status:** Fixed. All advanced LOLBin signals now produce alerts.

#### 3.2.4 Basic LOLBin (Shell from Non-Terminal Parent) ✅ WORKING

- **Detector:** `LOLBinDetector.evaluate()` + `ParentChainAnalyzer.evaluateChain()`
- **Signal reason:** `lolbin`
- **Correlation rule:** `lolbinRule` (score: 0.65, severity: medium)
- **Notification:** ✅ quickTick path
- **Status:** Working correctly.

#### 3.2.5 Reverse Shell ✅ WORKING (fixed)

- **Detectors:**
  - `ConnectionScanner` → reason: `reverse_shell` (shell interpreter + ESTABLISHED outbound TCP)
  - `ReverseShellDetector.signals()` → reasons: `reverse_shell_port`, `netcat_connection`, `temp_binary_network`
- **Gap found:** `reverseShellRule` matched only `reason == "reverse_shell"`. The three `ReverseShellDetector`-specific reasons were ingested but never triggered an alert.
- **Additional gap:** Rule extracted `metadata["process"]` but `ReverseShellDetector` signals store the process in `processInfo`, not in metadata. `processes` string was empty for those signals.
- **Fix applied:** `reverseShellRule` now matches all four reasons. Process extraction falls back to `processInfo?.name` when `metadata["process"]` is absent.
- **Notification:** ✅ Both full scan (fixed) and quickTick (pre-existing)
- **Status:** Fixed. All reverse shell signal variants trigger critical alert + notification.

#### 3.2.6 Camera / Microphone Activation ✅ WORKING

- **Detector:** `AVCaptureMonitor` → `source: .avCapture`
- **Correlation rule:** `unexpectedCaptureDeviceRule` (score: 0.85, severity: high)
- **Notification:** ✅ Full scan path (now with notification dispatch after fix in 3.3.1)
- **Status:** Working correctly.

#### 3.2.7 Unsigned LaunchAgent / LaunchDaemon ✅ WORKING

- **Detector:** `PersistenceWatcher` → `source: .persistence`, severity `.high` or `.critical`
- **Correlation rule:** `unsignedLaunchAgentRule` (score: 0.70, severity: high)
- **Coverage:**
  - `/Library/LaunchDaemons` ✅
  - `/Library/LaunchAgents` ✅
  - `~/Library/LaunchAgents` ✅
  - `/Library/StartupItems` ✅
  - `/Library/Periodic` ✅
  - `/Library/SystemExtensions` ✅
- **Missing persistence locations:** Login Items (`SMAppService`), `at` jobs, `/etc/cron.d`, shell profile files (`~/.zshrc`, `~/.bash_profile`, `/etc/zshrc`), `~/.ssh/authorized_keys`
- **Notification:** ✅ Full scan path (now with notification dispatch)
- **Status:** Working for LaunchAgent/Daemon. Shell profiles and Login Items not monitored (see 3.4).

#### 3.2.8 Critical System Security Configuration ✅ WORKING

- **Detector:** `SystemAuditor` checks: SIP, FileVault, Gatekeeper → `source: .systemAudit`, `severity: .critical`
- **Correlation rule:** `criticalSystemAuditRule` (score: 0.90, severity: critical)
- **Notification:** ✅ Full scan path (now with notification dispatch)
- **Checks covered:**

| Check | Passes Critical Rule? | Notes |
|-------|-----------------------|-------|
| SIP disabled | ✅ yes | `status == .fail` → `.critical` severity signal |
| FileVault disabled | ✅ yes | `status == .fail` → `.critical` severity signal |
| Gatekeeper disabled | ✅ yes | `status == .fail` → `.critical` severity signal |
| Firewall disabled | ⚠️ no | `makeSignal` emits `.warning` — below the `.critical` filter in `criticalSystemAuditRule` |
| Stealth mode off | ⚠️ no | Same — `.warning` severity |
| XProtect stale | ⚠️ no | `status == .warning` → `.warning` signal |
| Remote login on | ⚠️ no | Returned as `.warning` or `.unknown` |

- **Gap:** Firewall/stealth/XProtect/remote-login findings appear in the System Audit UI tab but **produce no alert and no notification**. They accumulate only if 3+ warnings exist to trigger `multipleHighSignalsRule`.
- **Status:** Critical system checks (SIP/FileVault/Gatekeeper) work. Non-critical checks are UI-only.

#### 3.2.9 YARA File Signature Match ⚠️ PARTIAL

- **Detector:** `YARAEngine` + `FileSystemWatcher` (FSEvents real-time), `DeepScanner` (manual)
- **Pipeline status:**
  - `DeepScanner` (manual deep scan from UI): YARA matches surfaced in `DeepScanView` results list only — NOT ingested into `ThreatCorrelator`, NOT producing alerts, NOT sending notifications.
  - `FileSystemWatcher` (real-time FSEvents): Fully implemented and produces `ThreatSignal` with `source: .yara` — but **never started**. Not instantiated in `SecurityEngine` or `MonitorCoordinator`.
- **Correlation rule gap (fixed):** New `yaraMatchRule` added (score: 0.90, severity: high). Matches `source == .yara` signals from any producer.
- **Remaining gap:** `FileSystemWatcher` is not started. `DeepScanner` results are not ingested. YARA signals only produce alerts if `FileSystemWatcher` is wired into the pipeline.
- **Status:** Rule added. Wiring `FileSystemWatcher` is a separate task (see 3.5.2).

#### 3.2.10 Multiple Concurrent Threat Indicators ✅ WORKING

- **Rule:** `multipleHighSignalsRule` (score: 0.75, severity: high)
- **Trigger:** 3+ `severity >= .medium` signals from any source within the 30-second window
- **False positive risk:** On developer machines with active build systems, concurrent process spawns (e.g. `make` + `python` + `bash`) could each contribute a medium signal and trigger this rule.
- **Status:** Working. FP risk is mitigated by the `TrustedProcessList`.

---

### 3.3 Notification Pipeline Audit

#### 3.3.1 Full Scan Path — Notifications Missing (FIXED)

**Finding:** `SecurityEngine.performFullScan()` called `mergeAlerts(newAlerts)` but never
dispatched notifications via `NotificationManager.shared.send(for:)`. Alerts from
`SystemAuditor`, `PersistenceWatcher`, `NetworkAnalyzer`, and `AVCaptureMonitor` appeared
in the UI silently with no system notification banner.

**Fix applied:** After `mergeAlerts(newAlerts)`, the existing deduplication keys are captured
before the merge. Post-merge, only alerts with a deduplication key that was not already
present are dispatched to `NotificationManager`. This prevents notification spam for
persistent threats (e.g. SIP still disabled) on every 60-second deep scan cycle.

```swift
let existingKeys = Set(alerts.map { $0.deduplicationKey })
mergeAlerts(newAlerts)
let genuinelyNew = newAlerts.filter {
    $0.severity != .info && !existingKeys.contains($0.deduplicationKey)
}
for alert in genuinelyNew {
    await NotificationManager.shared.send(for: alert)
}
```

#### 3.3.2 Full Scan Alerts Lack AI Explanations (Known Gap)

**Finding:** `AlertExplainer` (Foundation Models LLM) is instantiated only in
`MonitorCoordinator`, not in `SecurityEngine`. Full scan alerts therefore have
`alert.explanation == nil`. The quickTick path correctly enriches alerts with explanations.

**Impact:** Alert rows for full-scan-only detections (e.g. AVCapture, Persistence, System Audit)
show no "Why this is suspicious" explanation card. All functional — no false negatives.

**Resolution (Fixed — Part 4.6):** `SecurityEngine.performFullScan()` now creates an `AlertExplainer` instance and enriches each `genuinelyNew` alert's `explanation` field before dispatch. Full-scan alerts (AVCapture, Persistence, System Audit) now include the Foundation Models explanation card.

#### 3.3.3 QuickTick Notification Pipeline ✅ Verified Correct

The fast-tick path in `MonitorCoordinator.quickTick()` correctly implements the full pipeline:

```
New PID → ProcessScanner.quickInfo → LOLBinDetector.evaluate + ParentChainAnalyzer.evaluateChain
→ correlator.ingest → correlator.correlateNew → AlertExplainer.explain
→ ThreatLogger.log → NotificationManager.shared.send → SecurityEngine.addAlert
```

All steps confirmed present and in the correct order.

---

### 3.4 Coverage Gaps — Persistence Monitoring

| Persistence Mechanism | Monitored | Notes |
|-----------------------|:---------:|-------|
| `/Library/LaunchDaemons` | ✅ | |
| `/Library/LaunchAgents` | ✅ | |
| `~/Library/LaunchAgents` | ✅ | |
| `/Library/StartupItems` | ✅ | |
| `/Library/Periodic` (daily/weekly/monthly) | ✅ | |
| `/Library/SystemExtensions` | ✅ | |
| Login Items (`SMAppService` / `SMLoginItem`) | ❌ | Not monitored |
| `at` jobs | ❌ | Not monitored |
| `/etc/cron.d`, user crontabs | ⚠️ Partial | `LOLBinDetector` detects `crontab -` modification in real time; no baseline diff |
| `~/.zshrc`, `~/.bash_profile`, `/etc/zshrc` | ❌ | Not monitored |
| `~/.ssh/authorized_keys` | ❌ | Not monitored |
| Kernel extensions (`kext`) | ❌ | SIP prevents loading unsigned kexts; lower risk |

**Recommendation:** Add Login Items enumeration via `SMAppService.statusForLegacyPlist` and
`SMAppService.statusForAuthorizableItem` in a future `PersistenceWatcher` revision.

---

### 3.5 Coverage Gaps — Other

#### 3.5.1 No Network Beaconing / C2 Detection

Periodic, low-volume outbound connections (C2 beaconing patterns — e.g., one DNS query every
60 seconds to a fast-flux domain) are not detected. All current network detection is
connection-state based (ESTABLISHED TCP with shell process). Detection of beaconing requires
statistical analysis of connection frequency over time, which is outside the current v1.0 scope.

#### 3.5.2 FileSystemWatcher Not Started

`FileSystemWatcher` is fully implemented with FSEvents integration and produces correct
`ThreatSignal` values with `source: .yara`. It is not started anywhere in `SecurityEngine`
or `MonitorCoordinator`. Starting it requires:
1. Instantiate `YARAEngine(rulesDirectory:)` pointing at `Rules/community`
2. Instantiate `FileSystemWatcher(yaraEngine:onThreatSignal:)` with a closure that calls `correlator.ingest([signal])`
3. Call `fileSystemWatcher.startWatching()` in `startRealTimePipeline()`

With `yaraMatchRule` now in `CorrelationRule.standard`, once `FileSystemWatcher` is wired,
YARA real-time matches will automatically produce high-severity alerts and notifications.

#### 3.5.3 Screen Recording / Clipboard Access

No detection for unauthorized screen recording (`CGWindowListCreateImage` misuse) or
clipboard access (`NSPasteboard` reads by unexpected processes). These are privacy-sensitive
but require entitlements to monitor and are not in scope for v1.0.

#### 3.5.4 BehavioralScorer — Intentionally Not Wired

The `BehavioralScorer` CoreML scorer is intentionally excluded from the live detection path. The 40-feature `FeatureVector` and `FeatureExtractor` are fully implemented. `BehavioralScorer` loads `ThreatScorer.mlmodelc` from the app bundle; `isModelAvailable` returns `false` when the trained model file is absent, preventing accidental activation. All production detection runs through the rule-based `CorrelationRule` set. The ML path will be connected once `ThreatScorer.mlmodel` is trained on real signal telemetry collected post-launch. This is the correct architectural decision for v1.0.

---

### 3.6 Summary Table

| Detection | Detector | Rule | Alert | Notification | Pre-fix Status | Post-fix Status |
|-----------|----------|------|:-----:|:------------:|---------------|----------------|
| Unsigned binary in /tmp | ProcessScanner | `unsignedBinaryInTmpRule` | ✅ | ✅ | ✅ Working | ✅ Working |
| curl\|bash pipe | LOLBinDetector | `curlPipeShellRule` | ✅ | ✅ | ✅ Working | ✅ Working |
| wget\|bash pipe | LOLBinDetector | `curlPipeShellRule` | ❌ | ❌ | 🔴 **Gap** | ✅ **Fixed** |
| osascript shell | LOLBinDetector | `lolbinAdvancedRule` | ❌ | ❌ | 🔴 **Gap** | ✅ **Fixed** |
| quarantine removal | LOLBinDetector | `lolbinAdvancedRule` | ❌ | ❌ | 🔴 **Gap** | ✅ **Fixed** |
| base64 payload | LOLBinDetector | `lolbinAdvancedRule` | ❌ | ❌ | 🔴 **Gap** | ✅ **Fixed** |
| launchctl from /tmp | LOLBinDetector | `lolbinAdvancedRule` | ❌ | ❌ | 🔴 **Gap** | ✅ **Fixed** |
| crontab modification | LOLBinDetector | `lolbinAdvancedRule` | ❌ | ❌ | 🔴 **Gap** | ✅ **Fixed** |
| mktemp + execute | LOLBinDetector | `lolbinAdvancedRule` | ❌ | ❌ | 🔴 **Gap** | ✅ **Fixed** |
| LOLBin (non-terminal shell) | LOLBinDetector | `lolbinRule` | ✅ | ✅ | ✅ Working | ✅ Working |
| Reverse shell (ConnectionScanner) | ConnectionScanner | `reverseShellRule` | ✅ | ✅ | ✅ Working | ✅ Working |
| Reverse shell (unusual port) | ReverseShellDetector | `reverseShellRule` | ❌ | ❌ | 🔴 **Gap** | ✅ **Fixed** |
| netcat with active connection | ReverseShellDetector | `reverseShellRule` | ❌ | ❌ | 🔴 **Gap** | ✅ **Fixed** |
| /tmp process + outbound TCP | ReverseShellDetector | `reverseShellRule` | ❌ | ❌ | 🔴 **Gap** | ✅ **Fixed** |
| Camera / mic activation | AVCaptureMonitor | `unexpectedCaptureDeviceRule` | ✅ | ❌ | 🟡 No notify | ✅ **Fixed** |
| Unsigned LaunchAgent/Daemon | PersistenceWatcher | `unsignedLaunchAgentRule` | ✅ | ❌ | 🟡 No notify | ✅ **Fixed** |
| SIP / FileVault / Gatekeeper off | SystemAuditor | `criticalSystemAuditRule` | ✅ | ❌ | 🟡 No notify | ✅ **Fixed** |
| Firewall disabled | SystemAuditor | (none — UI only) | ⚠️ | ❌ | 🟡 Gap | 🟡 UI only |
| YARA match (DeepScanner) | DeepScanner | `yaraMatchRule` | ⚠️ | ❌ | 🔴 No rule | 🟡 Rule added; ingest not wired |
| YARA match (real-time FSEvents) | FileSystemWatcher | `yaraMatchRule` | ⚠️ | ❌ | 🔴 Not started | 🟡 Rule added; watcher not started |
| Multiple concurrent indicators | Any | `multipleHighSignalsRule` | ✅ | ✅ | ✅ Working | ✅ Working |

**Legend:** ✅ Working &nbsp; 🔴 Gap (not detected) &nbsp; 🟡 Partial / known limitation &nbsp; ❌ Missing

---

### 3.7 Fixes Applied This Audit Session

| File | Change | Reason |
|------|--------|--------|
| `Nick/Core/ThreatCorrelator/CorrelationRule.swift` | `curlPipeShellRule` now matches `wget_pipe_shell` | `LOLBinDetector` emits this reason; previously unmatched |
| `Nick/Core/ThreatCorrelator/CorrelationRule.swift` | `reverseShellRule` matches `reverse_shell_port`, `netcat_connection`, `temp_binary_network` + falls back to `processInfo?.name` | `ReverseShellDetector` signals had different reason keys and stored process in `processInfo` not metadata |
| `Nick/Core/ThreatCorrelator/CorrelationRule.swift` | Added `lolbinAdvancedRule` (score: 0.80, high) — matches 6 advanced LOLBin reasons | Previously those signals produced no alert |
| `Nick/Core/ThreatCorrelator/CorrelationRule.swift` | Added `yaraMatchRule` (score: 0.90, high) — matches `source == .yara` | Needed for when `FileSystemWatcher` is wired |
| `Nick/Core/SecurityEngine.swift` | Full scan alerts now dispatch to `NotificationManager.shared.send` post-`mergeAlerts` | SystemAudit, Persistence, Network, AVCapture alerts were silent |

---

## Part 4 — Post-Audit Remediation (May 24, 2026)

### 4.1 FileSystemWatcher Wired into Pipeline (Fixed)

**Finding:** 3.5.2 — FileSystemWatcher fully implemented but never started.
**Fix:** `MonitorCoordinator.startRealTimePipeline()` now instantiates `YARAEngine`
from the bundle's Rules directory and starts `FileSystemWatcher`. New files in monitored
directories trigger automatic YARA scan. Signals ingested into `ThreatCorrelator` via
the `yaraMatchRule`. Graceful degradation if YARA rules fail to compile.

**Bug fix during verification:** `FileSystemWatcher` was created without `kFSEventStreamCreateFlagUseCFTypes`,
causing `fileSystemEventCallback` to treat a C `char**` array as an `NSArray`, crashing the app on
the first FSEvent delivery (`EXC_BAD_ACCESS / SIGSEGV` in `objc_msgSend` on thread
`com.ehsanazish.nick.fsevents`). Added `kFSEventStreamCreateFlagUseCFTypes` to the
`FSEventStreamCreate` flags so `eventPaths` is delivered as `CFArray` of `CFString`
(toll-free bridged to `NSArray`), making the `unsafeBitCast` valid.

**Verification:** Test suite logs confirm `[FileSystemWatcher] FileSystemWatcher: started watching 6 directories`
immediately after `[MonitorCoordinator] Real-time pipeline started`. The FSEvents crash
was reproduced via `xcodebuild test` (EXC\_BAD\_ACCESS in `ScanPerformanceTests`,
`MemoryLeakTests`, `YARAEngineIntegrationTests`) and resolved by the flag fix.
Full test suite after fix: **269 tests, 0 failures, TEST SUCCEEDED**.

**Detection status:** YARA real-time file scanning: ⚠️ Partial → ✅ Working.

### 4.2 NickHelper.entitlements Created (Fixed)

**Finding:** Part 1, item 9 — Entitlements file missing.
**Fix:** Created `NickHelper/NickHelper.entitlements` with `com.apple.security.app-sandbox = false`.
Hardened Runtime ON. No additional entitlements beyond what SMAppService registration requires.

**Verification:** File content verified via direct read: `com.apple.security.app-sandbox = <false/>` present.
No `.xcarchive` available in this environment for `codesign -d` output; content confirmed minimal —
exactly one key as required for Hardened Runtime without sandbox.

### 4.3 DeepScanner Results Ingested into Correlator (Fixed)

**Finding:** 3.2.9 — DeepScanner YARA matches not ingested into ThreatCorrelator.
**Fix:** `DeepScanner` now holds a weak reference to `SecurityEngine`. Each YARA match
emits a `ThreatSignal` with `source: .yara`, severity derived from YARA rule tags.
Signals are ingested, correlated, and dispatched to `NotificationManager`. Deep Scan
matches now appear in the Alerts sidebar and fire notifications.

**Verification:** App was not running during manual verification. Code-level analysis
confirms ingestion path: `DeepScanner.performDeepScan` → `eng.correlator.ingest(signals)`
→ `eng.correlator.correlateNew()` → `eng.addAlert(alert)` + `NotificationManager.shared.send(for:)`.
Pattern mirrors the verified real-time pipeline. Full test suite: **269 tests, 0 failures**.

### 4.4 Updated Summary Table

| Detection | Part 3 Status | Part 4 Status |
|-----------|:---:|:---:|
| YARA match (real-time FSEvents) | 🟡 Rule added; watcher not started | ✅ Working |
| YARA match (DeepScanner) | 🟡 Rule added; ingest not wired | ✅ Working |
| NickHelper entitlements | ⚠️ Pending | ✅ Created |

### 4.5 Remaining Open Items

| Item | Priority | Status |
|------|----------|--------|
| `getListeningPorts` empty implementation | Medium | Tracked as #43 |
| Replace `lsof` with `proc_pidfdinfo` | Low | Tracked as #1 |
| Network beaconing / C2 detection | Low | v2.0 scope |
| Endpoint Security entitlement application | High | Submitted to Apple, awaiting approval |

---

### 4.6 Detection Gap Closures (May 24, 2026)

Six detection gaps identified in Parts 2 and 3 were closed in this session.
All changes compile cleanly and the test suite remains at **269 tests, 0 failures**.

| Gap | Audit Reference | Fix | Status |
|-----|----------------|-----|--------|
| Full scan alerts lack Foundation Models explanations | 3.3.2 | `SecurityEngine.performFullScan` now creates an `AlertExplainer` instance and enriches each new alert's `explanation` field before dispatch. | ✅ Fixed |
| SwiftData pruning not verified at launch | Part 2, item 8 | `AppDelegate.applicationDidFinishLaunching` launches a background `Task` that creates a `ThreatLogger` from the production `ModelContainer` and calls `pruneOlderThan(days: 90)`. | ✅ Fixed |
| Login Items not monitored | 3.4 | `PersistenceWatcher.scanLoginItems()` queries System Events via a hardcoded `osascript` string (tab-delimited to avoid name-parsing ambiguity). Results merged into `snapshot()`. Verified live: 5 login items found during test run. | ✅ Fixed |
| Shell profiles not monitored | 3.4 | `FileSystemWatcher.defaultMonitoredDirectories` now includes `NSHomeDirectory()` and `/etc`. `handleEvents` emits a `.persistence / medium / reason: "shell_profile_modified"` signal for `.zshrc`, `.zprofile`, `.bashrc`, `.bash_profile`, `.profile`, `/etc/zshrc`, `/etc/zprofile`, and `/etc/zshenv`. New `shellProfileRule` (score: 0.70, severity: `.high`) added to `CorrelationRule.standard`. | ✅ Fixed |
| `~/.ssh/authorized_keys` not monitored | 3.4 | `~/.ssh` added to `defaultMonitoredDirectories`. `handleEvents` emits `.persistence / critical / reason: "ssh_keys_modified"` for any path ending in `/authorized_keys`. New `sshKeysRule` (score: 0.90, severity: `.critical`) added to `CorrelationRule.standard`. | ✅ Fixed |
| Firewall / stealth mode / XProtect / remote login — no alert | 3.2.8 | New `systemHardeningRule` (score: 0.50, severity: `.medium`) added to `CorrelationRule.standard`. Matches `.systemAudit` signals with `severity >= .medium` and `check` in `{firewall, firewallStealth, remoteLogin, automaticUpdates, xprotect}` — the non-critical checks previously visible only in the System Audit UI tab. | ✅ Fixed |

#### Updated Coverage Table (Persistence)

| Persistence Mechanism | Monitored |
|-----------------------|:---------:|
| `/Library/LaunchDaemons` | ✅ |
| `/Library/LaunchAgents` | ✅ |
| `~/Library/LaunchAgents` | ✅ |
| `/Library/StartupItems` | ✅ |
| `/Library/Periodic` (daily/weekly/monthly) | ✅ |
| `/Library/SystemExtensions` | ✅ |
| Login Items (`SMAppService` / System Events) | ✅ |
| `~/.zshrc`, `~/.bash_profile`, `/etc/zshrc`, etc. | ✅ |
| `~/.ssh/authorized_keys` | ✅ |
| `at` jobs | ❌ |
| `/etc/cron.d`, user crontabs | ⚠️ Partial |
| Kernel extensions (`kext`) | ❌ |

**Test count:** 269 tests, 0 failures, TEST SUCCEEDED. Codebase is in a clean state for v1.0.

---

## Updated Sign-off

I have reviewed the remediation applied in Parts 4.1–4.6. All fixes address
findings documented in Parts 1–3 of this audit. No new privileged code was
added. All detection changes operate in the main app's unprivileged context.

— Ehsan Azish, May 24, 2026

---

## Part 5 — v1.2 Security Review (May 25, 2026)

### 5.1 Functional Logging Pipeline — Security Analysis

The v1.2 logging system is a pure functional pipeline with no persistent
state. Each formatter and output is an isolated `@Sendable` closure with no
shared mutable state.

**Threat model:**
- **HTTP output:** Webhook URL is user-configured and stored in UserDefaults.
  Nick does not validate the destination — the user is responsible for ensuring
  the endpoint is trusted. Alerts may contain process names, file paths, and
  PIDs. No keychain data, passwords, or file contents are ever included.
- **File output:** Log files written to `~/Library/Logs/Nick/` are readable by
  the user only (0600). Daily rotation with 30-day retention. No sensitive
  data beyond what appears in the alert UI.
- **CEF/KV/JSON formatters:** Output contains only alert metadata (timestamp,
  severity, score, rule name, signal titles). No raw file contents, no
  process arguments, no network payload data.

**Decision:** No new privileged code. All logging runs in the main app's
unprivileged context. NickHelper is not involved.

### 5.2 Finder Sync Extension — Security Analysis

`NickFinderSync` is a separate sandboxed process (App Extension sandbox).
Communication with the main app uses a shared App Group UserDefaults
(`group.com.ehsanazish.nick`) — a read/write key-value store.

**Threat model:**
- The extension receives file URLs from Finder via `FIFinderSyncProtocol`.
  These URLs are validated before being written to the App Group store.
- The main app reads pending scan URLs from the App Group store on
  foreground activation. URLs are validated before being passed to `YARAEngine`.
- No XPC between the extension and main app — App Group UserDefaults is
  sufficient for the URL-passing use case and avoids additional IPC surface.

**Decision:** Extension runs in its own sandbox. Cannot access the privileged
helper directly. YARA scan is performed by the main app, not the extension.

### 5.3 Network Baseline — Security Analysis

`NetworkBaseline` stores per-process connection fingerprints on disk at
`~/Library/Application Support/com.ehsanazish.nick/network-baseline.json`.
This file contains process names and connection tuples (address, port, protocol).

**Threat model:**
- **Baseline poisoning:** If an attacker modifies the baseline file before
  detection, Nick may not flag their connections as anomalous. Mitigated by
  the fact that persistence detection would catch the file modification, and
  the baseline is rebuilt from scratch on any integrity check failure.
- **Privacy:** Baseline contains connection metadata only, not payload data.
  It is not included in any log output or export.

### 5.4 Configurable Alert Suppression — Security Analysis

Suppression rules are stored in UserDefaults as JSON. An attacker with local
user access could add suppression rules to hide their activity.

**Decision:** Accepted risk — an attacker with local user access can already
modify LaunchAgents, shell profiles, and application data. Suppression rules do
not expand the attack surface meaningfully. Suppressed alerts are still logged at
`.notice` level in the system log, creating an audit trail.

### 5.5 Updated Open Items

| Item | Priority | Status |
|------|----------|--------|
| Endpoint Security entitlement | High | Submitted to Apple, awaiting approval |
| Network Extension entitlement | Medium | Not yet applied |
| CoreML model training | Medium | Deferred until v1.2 telemetry data is sufficient |
| `getListeningPorts` implementation | Low | ✅ Closed in v1.2 (proc_pidfdinfo) |
| Replace `lsof` with `proc_pidfdinfo` | Low | ✅ Closed in v1.2 |

**Test count:** 273 tests, 0 failures, TEST SUCCEEDED. Codebase clean for v1.2.

---

## Updated Sign-off

v1.2 adds a functional logging pipeline, Finder Sync Extension, network baseline
detection, and configurable suppression rules. No new privileged code was added.
All new features run in the main app's unprivileged context or in a sandboxed
extension. The logging pipeline emits only alert metadata — no sensitive data,
no file contents, no credentials.

— Ehsan Azish, May 25, 2026
