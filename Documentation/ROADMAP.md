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

Maintenance releases in the 4.6.x line continue for security fixes and for
making in-app wording match exactly what each protection does.

## Version 5.0: trustworthy by design (in development)

Nick 5.0 is a larger internal redesign. It ships when its measured release
gates pass, not on a fixed date. Planned capabilities:

**One evidence pipeline**
- Endpoint Security, Network Extension, Deep Scan, file-system and app-level
  monitors feed one typed evidence model and one incident store.
- Every finding that matters appears once in Activity, with one severity,
  one set of suppressions, and a persisted history.
- Real-time findings and Scam Guardian observations notify the user.

**Narrower privileges and stable file identity**
- Per-action authorization between the app and the extension.
- Quarantine and allow-once bound to file identity, not paths.
- Security settings stored and changed through the protected extension store.
- Durable file-integrity evidence that changes only when the user
  acknowledges it.

**Detection integrity**
- Trust decisions based on verified signing identity, never process names.
- Measured Endpoint Security coverage of common download, archive, mail and
  launch paths.
- Bounded, observable file-event processing with dropped-event counters.
- Process genealogy and self-tamper protection either activated and tested,
  or removed.
- Bundled, versioned exact-hash intelligence available immediately after
  installation.

**Honest, visible protection**
- Protection status generated from live component health.
- A diagnostics view for sensor coverage, dropped events and update status.
- Nick reports when its own extension, health or settings change unexpectedly.

**Release gates**
- Endpoint Security authorization latency, event loss, CPU, memory and energy
  measured on every release.
- False-positive testing on a benign corpus and real developer workloads.
- Adversarial tests for file replacement, symbolic-link redirection, burst
  writes and settings tampering.
- An independent security review of the privileged paths before 5.0 is
  described as complete.

## Version 5.1: trusted rule and signature updates

- Publish Nick-maintained, signed YARA, network-rule and hash bundles.
- Add staged rollout, expiry, rollback, and last-known-good recovery.
- Display rule source, version, signing status, and last successful update.
- Add deterministic false-positive tests before accepting a rule bundle.
- Keep rules usable offline after verification.
- Optional, opt-in network blocking for high-confidence signed rules.

No unsigned community rule is eligible for automatic enforcement.

## Later: behavioral model

- Train and evaluate the CoreML behavioral model on consented, de-identified
  signal data.
- Publish evaluation methodology, false-positive rate, and model limitations.
- Keep deterministic rules as an explainable fallback.
- Require model output to be supported by observable security evidence.
- Provide local reset, export, and opt-out controls.

## Deferred unless a concrete requirement appears

- Packet-tunnel or full VPN operation.
- TLS interception or page-content inspection.
- Cloud upload of browsing history, mail content, or raw security events.
- Automatic deletion based solely on a heuristic or model score.
- A dedicated DNS proxy when the content filter already provides the required
  hostname enforcement.
