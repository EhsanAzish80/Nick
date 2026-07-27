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

The clean-Mac checklist remains the release gate for every published build.

## Version 4.1: reliability and explainability

- Persist setup diagnostics that users can export without exposing personal
  content.
- Group repeated alerts by app, behavior, and time window.
- Improve accepted-behavior management with review, expiry, and revocation.
- Add clearer provenance for downloaded, mail, browser, and temporary files.
- Replace remaining subprocess-based process and connection inspection with
  direct macOS APIs where practical.
- Expand Email Guard fixtures across supported Apple Mail and Outlook layouts.
- Add update and uninstall regression tests for active system extensions.
- Establish resource budgets for idle CPU, memory, event throughput, and scan
  concurrency in CI and release acceptance.

## Version 4.2: trusted rule updates

- Publish Nick-maintained, signed YARA and network rule bundles.
- Add staged rollout, expiry, rollback, and last-known-good recovery.
- Display rule source, version, signing status, and last successful update.
- Add deterministic false-positive tests before accepting a rule bundle.
- Keep rules usable offline after verification.

No unsigned community rule is eligible for automatic enforcement.

## Version 5.0: behavioral model

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
