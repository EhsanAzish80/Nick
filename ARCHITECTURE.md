# Nick Architecture

This document describes the architecture implemented in Nick 4.6.3. It is for
contributors and reviewers who want to understand the product's current
boundaries. Planned and inactive components are identified explicitly.

## Product boundary

Nick is a local macOS security and diagnostic application. The current release
contains a user-session app and two system extensions:

```text
Nick.app
├── SecurityEngine and MonitorCoordinator
├── process, persistence, connection, capture, and system-audit monitors
├── Deep Scan, Runtime Compare, quarantine UI, reports, and setup
├── ExtensionXPCClient
└── NetworkProtectionManager

NickExtension.systemextension
├── EndpointSecurityClient and authorization handlers
├── FileScanner, SHA-256 cache, and vendored libyara 4.5.5
├── email attachment and external-volume scanning
├── ransomware, file-integrity, and privacy monitoring
├── quarantine
└── authenticated XPCServer

NickNetFilter.systemextension
├── NEFilterDataProvider
├── NetworkProtectionPolicy and ScamGuardian
├── signed-envelope validation infrastructure
└── bounded health and observation-event persistence
```

Installation is not treated as proof that protection is running. The app uses
fresh health records and live XPC status before presenting a component as
active.

## Active data flows

Nick currently has four related but separate detection paths. They do not all
feed one central correlator.

### Endpoint Security

`NickExtension` subscribes to Endpoint Security authorization and notification
events. Authorization handlers perform bounded cache and exact-hash checks,
respond within the operating-system deadline, and move longer work off the ES
callback queue. Modified files can be scanned with YARA, evaluated for file
integrity, email attachment, and ransomware evidence, and reported to the app
over XPC.

The extension may deny a file operation when an exact curated hash is already
known or the user has explicitly promoted a reviewed finding to blockable.
Novel YARA findings are normally produced after the authorization response and
are presented for review rather than silently blocked.

### App monitoring and correlation

`SecurityEngine` runs local system-audit, persistence, process, connection, and
capture-device monitors. `MonitorCoordinator` performs lightweight process
checks every five seconds and schedules the more expensive full sweep no more
often than every five minutes.

These monitors emit `ThreatSignal` values. `ThreatCorrelator` retains a bounded
30-second window and applies deterministic `CorrelationRule` instances. Trusted
processes, suppression rules, stable incident identities, and temporary
acknowledgements reduce repeated or low-confidence alerts.

The main app and `MonitorCoordinator` currently own separate correlator
instances. Endpoint Security events are displayed through the extension event
client but are not generally converted into app-level `ThreatSignal` values.
Nick should therefore be described as correlating app-level signals, not as
combining every detector in one global scoring engine.

### YARA and Deep Scan

`YARAEngine` wraps vendored libyara 4.5.5. Rule files are validated separately,
compiled into immutable rule sets, and scanned with bounded concurrency and a
10-second per-file timeout.

`DeepScanner` streams candidate discovery and scanning concurrently. Match
classification considers rule class and severity, file format, verified
development layouts, Homebrew receipts, signed application context, and code
signing state. Concrete family signatures remain actionable regardless of
path; broad behavior matches can remain visible without becoming alerts.

An FSEvents watcher provides additional YARA coverage for newly created or
modified executable content in selected directories.

### Network observation

`NickNetFilter` receives socket-flow metadata from Network Extension. It can
evaluate hostname or IP, remote port, source application identity, bundled
lookalike-domain logic, and any locally installed valid signed rule envelope.
It does not inspect payloads, page contents, URL paths, query strings, or form
data.

The shipping provider is observation-only and returns an allow verdict for all
flows. Missing, stale, or invalid configuration also fails open. Network
observations are stored locally in a bounded app-group record.

## Alert and response flow

```text
local monitor signals
        │
        ▼
deterministic correlation rules
        │
        ▼
ThreatAlert ──► on-device Apple Foundation Models explanation
        │                     (text only)
        ├──► app UI and local notification
        ├──► optional local file/stdout output
        └──► optional user-configured webhook

Endpoint Security findings ──► XPC event/timeline and quarantine state
Network Extension findings  ──► local network observation store
```

Apple Foundation Models runs only after deterministic code has created an
alert. Generated text cannot alter severity, scoring, Endpoint Security
authorization, quarantine, process termination, or network policy. If model
generation is unavailable, Nick uses a deterministic template.

## Major components

| Component | Current responsibility |
|---|---|
| `SecurityEngine` | Main-actor application state, full scans, app-level correlation, alerts, explanations, and statistics. |
| `MonitorCoordinator` | Five-second process checks, scheduled full scans, and ownership of the FSEvents YARA watcher. |
| `ThreatCorrelator` | Bounded signal window, deterministic rules, suppression, trusted-process adjustment, and incident deduplication. |
| `DeepScanner` | Candidate enumeration, contextual YARA classification, progress, cancellation, and scan results. |
| `YARAEngine` | Rule validation, compilation, and bounded libyara scanning. |
| `NickExtension` | Endpoint Security events, authorization decisions, file scanning, ransomware/FIM/privacy/email/USB monitoring, and quarantine. |
| `NickNetFilter` | Observation-only socket-flow classification and bounded local event storage. |
| `RuntimeCompare` | Local before-and-after snapshots, comparison, sanitization, and export. |
| `AlertExplainer` | Human-readable explanation using Apple Foundation Models; untrusted context is bounded and delimited, and generated text has no detection or enforcement authority. |
| `SignalTelemetry` | Optional, size-capped local JSONL export. It is off by default, user-writable, and never read as detection or learning input. |

## Apple frameworks and system APIs

The current source uses SwiftUI, AppKit, Observation, SwiftData, Endpoint
Security, Network Extension, Network, System Extensions, Service Management,
Security, CryptoKit, Foundation Models, User Notifications, AVFoundation,
CoreMediaIO, CoreAudio, IOKit, FSEvents/CoreServices, SQLite, and BSD/Darwin
process and filesystem APIs. Sparkle supplies signed application updates.

Core ML is present in inactive behavioral-scoring infrastructure. No production
model is bundled, Release builds can load only from the signed app bundle, and
missing or non-production models cannot return a score. The live correlation
path does not construct or invoke the scorer.

## Privileges and permissions

- `NickExtension` requires Apple's Endpoint Security client entitlement and
  user approval for its system extension.
- `NickNetFilter` requires the content-filter-provider system-extension
  entitlement and user approval.
- The parent application requires permission to install system extensions.
- Full Disk Access is needed for protected system and supported mail data.
- Notifications require user approval.
- Nick cannot grant these approvals itself.

The main application is not App Sandbox confined. Privileged Endpoint Security
and quarantine operations remain in `NickExtension`, outside the UI process.

## Trust and process boundaries

### Main app to Endpoint Security extension

The app and Endpoint Security extension communicate over `NSXPCConnection`.
The extension's listener requires the exact signed identity of the Nick app
(bundle identifier, Apple-issued certificate chain and team identifier) before
a connection reaches Nick's code. The expected identity is part of the signed
extension bundle; if it is missing, the listener does not start and the health
record reports it. Requests and events use typed XPC methods with JSON-encoded
value payloads.

The extension exposes status, reviewed allow/block actions, quarantine
operations, FIM baseline rebuilding, canary deployment, and bounded event
replay. It does not offer a general file-scan request: user-selected scans and
Deep Scan run in the app with the user's permissions.

The quarantine vault and extension databases live under
`/Library/Application Support/com.ehsanazish.nick`. The extension health
record there is readable by the app; persisted endpoint events are kept in a
separate subdirectory readable only by the extension and are delivered to the
app over XPC. Quarantine restore uses descriptor-based operations, refuses a
destination path that has been redirected through a symbolic link, and
restores the recorded ownership and permissions.

### Network extension

The Network Extension receives socket-flow metadata from macOS. It shares only
bounded configuration, health, and observation records with the parent app. It
does not receive file contents and does not send flow data to a Nick-hosted
service.

### Explicit outbound boundaries

Detection and analysis are local by default. Network activity in current source
is limited to explicit product functions:

- Sparkle update checks and downloads;
- an optional webhook configured by the user;
- links opened by the user;
- files the user manually exports and chooses to transmit.

Nick has no active hosted detection service or automatic security-telemetry
uploader. Optional training telemetry is disabled by default and stored locally
until the user exports it.

## Enforcement boundaries

- Exact curated hash evidence can be used for automatic file denial.
- Heuristic and ordinary YARA behavior matches are review findings unless the
  user explicitly blocks the reviewed file.
- Quarantine requests re-scan the current file before moving it.
- Ransomware response requires ransomware-specific evidence; entropy or file
  volume alone does not justify automatic action.
- Network Extension findings never interrupt traffic in the shipping provider.
- Language-model output never determines enforcement.

## Built but not active

The repository contains code that is not part of the current live product path:

- `BehavioralScorer`, feature extraction, and Core ML integration: no trained
  production model is bundled; non-production models fail closed; and the
  correlator does not invoke the scorer.
- `NickHelper`: the read-only helper target exists, but current builds do not
  embed its LaunchDaemon definition and the app has no live helper XPC client.
- `CloudIntelService`: hash lookup and update code exists but is not constructed
  or scheduled.
- `ProcessTree` and `TamperProtection`: implementations exist but are not
  instantiated in the Endpoint Security extension object graph.
- Production signed-rule delivery: verification structures exist, but no
  production key/feed, staged rollout, rollback, or last-known-good recovery is
  published.

See [the roadmap](Documentation/ROADMAP.md) for planned work. Code presence is
not treated as an implemented product capability.

## Known product limits

- Nick cannot guarantee detection of every threat.
- First execution of a novel file can occur before its background YARA result.
- The Network Extension observes destinations but does not block traffic.
- Size, timeout, concurrency, retention, and scan-location limits intentionally
  bound resource use and therefore bound coverage.
- Runtime Compare is observational and does not certify compliance or remediate
  MDM state.
- Nick does not inspect encrypted traffic or page content.
- Attacks that occur before Nick and its approved extensions are running are
  outside its observation window.
- Kernel compromise, physical access, and macOS vulnerabilities are outside the
  guarantees of this userspace application.

Security vulnerabilities should not be opened as public issues. Follow
[SECURITY.md](SECURITY.md) for private reporting.
