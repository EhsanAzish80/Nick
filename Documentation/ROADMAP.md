# Nick Roadmap

The roadmap favors verified protection, low false-positive rates, and modest
resource use over adding more labels or background monitors.

## Version 4.0

Delivered in source and release packaging:

- Endpoint Security real-time file and process protection.
- Scam Guardian Network Extension content filter with signed-rule support,
  allowlists, emergency disable, and privacy-safe events.
- Email Guard attachment monitoring through the Endpoint Security extension.
- Guided setup based on verified component health.
- File-aware alerts with safe quarantine actions.
- Threat Timeline and corrected empty states.
- YARA 4.5.5 and confidence-aware enforcement.
- Native uninstaller and signed installer/disk-image pipeline.
- Background performance, event-volume, and cache bounds.
- Version 4.0.1 safety correction: Scam Guardian is observation-only and the
  Network Filter cannot drop ordinary traffic.

The clean-Mac checklist remains the release gate for every published build.

## Version 4.1: Runtime Compare and Network Diagnostics

Released in build 416:

- Local, read-only before-and-after snapshots for processes, persistence,
  listeners, outbound connections, system extensions, and sensor health.
- Restart-resumable same-Mac comparison with deterministic stable identities.
- Evidence classification, provider-health limitations, and bounded retention.
- Sanitized Markdown and JSON support-bundle preview and export.
- Cross-restart process-noise suppression and deterministic handling of
  overlapping active and retiring system-extension records.
- Explicit limits for observation duration, imports, snapshots, connections,
  exports, and stored comparisons.

Nick 4.1 does not enforce compliance, remediate MDM state, block network
traffic, integrate with an MDM server, or collect fleet data.

The accepted product, UI, schema, privacy, testing, and implementation record
is maintained in the
[Nick 4.1 Runtime Compare roadmap](archive/NICK_4_1_RUNTIME_COMPARE_ROADMAP.md).

## Versions 4.2-4.4: detection accuracy and operational clarity

Delivered:

- Stronger contextual evidence for developer tools, shell activity, signed
  updaters, encrypted application caches, and application-managed data.
- Safer quarantine, restore, and remediation behavior for missing or changed
  evidence.
- Consistent active-alert badges and green, orange, and red menu bar state.
- Persistent Deep Scan with canonical deduplication and strict boundaries
  between contextual behavior matches and concrete malware signatures.
- Live process signing and threat assessment instead of all-unknown columns.
- Network Activity explanations for app identity, destination type, ports,
  observation reason, and allow-action scope.
- Actionable Overview attention summaries that identify the root cause and
  route users to the relevant evidence.

## Version 4.6: Simple mode and security hardening

Delivered:

- Simple and Advanced modes, with Simple as the default for new installs.
- Streamed Deep Scan progress.
- 4.6.3: hardened communication between the app and the Endpoint Security
  extension, protected local event storage, a safer quarantine restore, and
  less sensitive process information in diagnostic logs.

4.6.3 is the final 4.x feature release.

## Version 5.0: trustworthy by design

Released 2026-10-16.

- Redesigned Simple mode with Home, Scan, Activity, Protection, and Storage.
- Shared protection and incident display states across the five status views.
- Root-owned incident and security-settings stores with authenticated changes.
- Durable Endpoint Security finding delivery with persistence acknowledgement
  and a readiness gate.
- Responsible-app attribution with bounded process chains for behavior
  findings.
- Validated identity-based exclusion when Nick scans its own signed bundle.
- Nick self-file tamper protection and safer, file-identity-bound remediation.
- Completed-download exact-hash checks for bounded supported locations.
- Verified Sparkle updates and visible update status.
- Local L1-L2 verdict learning for review-tier findings, off by default, with
  inspection, export, and reset controls.
- Network findings remain in Network Activity and do not create alerts or
  notifications in 5.0.

## Version 5.0.1

- Deliver eligible network findings into Activity with notifications.
- Harden extension self-protection and continuity reporting.
- Harden protected-evidence lifecycle and write-authorization policy.
- Expand shell-pipeline detection coverage while retaining command evidence.
- Persist retention counters across processes and relaunches.
- Review generic scan downgrades for signed software.
- Add a built-product rule gate and keep production policy material out of
  built test artifacts.

## Version 5.1: trusted rule and signature updates

### Interface work

- Join related shell events into one incident chain.
- Reorganize Settings in both Simple and Advanced modes.
- Continue expanding the shared Simple and Advanced Storage screen. Nick 5.0
  credits its JunkYard-powered cleanup engine and links to the full JunkYard
  Cleaner App Store product from the Storage screen in both modes.

- Publish Nick-maintained, signed YARA, network-rule and hash bundles.
- Add staged rollout, expiry, rollback, and last-known-good recovery.
- Display rule source, version, signing status, and last successful update.
- Add deterministic false-positive tests before accepting a rule bundle.
- Keep rules usable offline after verification.
- Optional, opt-in network blocking for high-confidence signed rules.

No unsigned community rule is eligible for automatic enforcement.

## Version 5.2: expands local learning

- Expand the L1-L2 learning shipped in 5.0 to additional eligible local review
  decisions while keeping the feature off by default.
- Learning never hides signature, hash or YARA detections, and never applies
  to unsigned code or script interpreters.
- A "What Nick learned" view in Settings showing each learned entry, why it
  exists and when it expires, with reset and export.
- On-device incident summaries and plain-language help drafting suppression
  rules, which you review and confirm.
- Everything stays on your Mac.

## Later: behavioral model

- Per-app behavioral baselines with explainable novelty scores.
- Train and evaluate the CoreML behavioral model on consented, de-identified
  signal data.
- Publish evaluation methodology, false-positive rate, and model limitations.
- Keep deterministic rules as an explainable fallback.
- Require model output to be supported by observable security evidence.
- No model output triggers kill, quarantine or block on its own.
- Provide local reset, export, and opt-out controls.

## Deferred unless a concrete requirement appears

- Packet-tunnel or full VPN operation.
- TLS interception or page-content inspection.
- Cloud upload of browsing history, mail content, or raw security events.
- Automatic deletion based solely on a heuristic or model score.
- A dedicated DNS proxy when the content filter already provides the required
  hostname enforcement.
