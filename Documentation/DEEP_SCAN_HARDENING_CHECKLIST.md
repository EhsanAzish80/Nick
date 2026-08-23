# Deep Scan Hardening Checklist

This checklist records the security, false-positive, UI, and lifecycle review completed for Nick's deep scanner before the next release. The governing rule is that location or user trust may reduce noise from broad behavior heuristics, but must never override a concrete malware signature or critical evidence.

## Suppression safety

- [x] Scope development-context downgrades to broad behavioral rules. Concrete signatures remain threats in every path.
- [x] Require repository evidence (`.git`, `Package.swift`, `.swiftpm`, or `project.pbxproj`) instead of trusting attacker-controlled folder names such as `Sources`, `Tests`, or `node_modules`.
- [x] Remove broad `Application Support`, `Caches`, and `WebKit` ownership inference. Only exact signed-app container relationships qualify as application data.
- [x] Match container identifiers exactly, with only conventional `.data` and `group.<bundle>.shared` forms accepted.
- [x] Allow ignores and correlator path suppressions only for non-critical behavioral YARA findings. Concrete signatures, persistence, system-audit, and critical findings remain non-suppressible.
- [x] Canonicalize ignored paths and apply them before correlator ingestion and notification delivery.

## False-positive control

- [x] Default rules with missing severity metadata to Medium rather than High.
- [x] Validate that every bundled community rule declares an explicit severity.
- [x] Recognize unsigned Homebrew wrappers only when their resolved path belongs to a real Cellar keg with a Homebrew receipt. Lookalike directories do not qualify.
- [x] Keep scanning opaque cache data so concrete malware signatures cannot hide there, while downgrading only known broad cache-prone behavior rules. This intentionally avoids the blind spot that wholesale cache exclusion would create.
- [x] Scan launch-agent and launch-daemon property lists even though generic property lists remain excluded.
- [x] Deduplicate canonical rule/path pairs, including `/tmp` and `/private/tmp` aliases.

## Results integrity and UI

- [x] Produce `.threat` for concrete signatures and reserve contextual verdicts for broad behavioral rules.
- [x] Key verdicts and SwiftUI row identity by canonical path plus rule name.
- [x] Store classification during scanning instead of reclassifying every result serially in the view.
- [x] Keep the results header explicit about total rule matches versus findings that need review.
- [x] Do not display a green all-clear state while suspicious findings remain.
- [x] Hide the ignore action for concrete or critical findings.

## Scan lifecycle

- [x] Set the running state synchronously before creating the scan task, preventing overlapping starts.
- [x] Keep the scanner busy while an in-flight file scan responds to cancellation.
- [x] Check cancellation before result mutation, ingestion, and notifications.
- [x] Update completed-file progress and remaining-time estimates after every scanned file.
- [x] Keep one scanner instance on `SecurityEngine` so scans survive sidebar navigation.

## Verification coverage

- [x] Development-path bypass tests, including fake source paths and concrete signatures inside repositories.
- [x] Exact container ownership and lookalike-container tests.
- [x] Cache-context tests for Service Worker and Google Updater CRX data.
- [x] Homebrew receipt and lookalike-keg tests.
- [x] Launch-property-list enumeration-policy tests.
- [x] Rule severity metadata validation.
- [x] Rule/path identity and canonical deduplication tests.
- [x] Ignore/suppression boundary tests for behavioral versus concrete YARA evidence.
- [x] Double-start and cooperative-cancellation lifecycle tests.

## Release gates

- [x] Run the focused deep-scan and correlator test suites (58 passed, 0 failed).
- [x] Run the complete Nick test suite with code coverage enabled (406 executed: 402 passed, 4 skipped, 0 failed).
- [x] Build the unsigned Release configuration successfully.
- [ ] Perform a signed installed-build smoke test before publication. The signed package and DMG have passed notarization, stapling, and Gatekeeper; live extension approval remains a physical-system check.
- [x] Confirm unrelated working-tree files remain excluded; the existing untracked `Deployment/` directory was not modified or included in this work.
