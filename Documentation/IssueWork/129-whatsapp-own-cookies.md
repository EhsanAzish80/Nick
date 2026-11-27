# Issue #129: Investigate WhatsApp own-cookie denial

Related issue: [#129](https://github.com/EhsanAzish80/Nick/issues/129)

## Current status

Regression coverage and current-build verification; no new runtime policy change. The historical denial is not reproduced by the bounded current check, and its original cause remains unproven. The original issue remains open. Base checkpoint: `171d1a8b3aea0c59628cae5817bc95d98c4b3951`.

## Problem and scope

[False positive]: WhatsApp denied access to its own container cookie store

Trace validated store ownership, cookie-container classification, cold validation and post-update transitions for the reported own-container denial.

## Initial code review targets

These are investigation entry points, not established causes:

- `Shared/LOLBinExecutionPolicy.swift`
- `NickExtension/EventHandler.swift`
- `NickTests/CredentialAccessPolicyTests.swift`

## Scope boundaries

Preserve cross-app and unvalidated-actor protection. No blanket WhatsApp or cookie-directory allowlist.

This PR owns only issue #129. Keep implementation, tests and validation evidence in this branch. If shared code needs an earlier sibling change, document that dependency and rebase explicitly rather than bundling other issues into this PR.

## Acceptance and validation

The issue remains the source of the full report and acceptance criteria. Initial checklist:

- [x] Record the bounded current-build check and its limits below.
- [x] Add exact WhatsApp ownership and negative-case regressions; no historical cause is claimed.
- [x] Record positive and negative policy checks in Xcode.

- [ ] Record the confirmed cause and resulting implementation in this document.
- [x] Run focused Xcode regressions; do not label coverage as a runtime fix.
- [x] No enforcement, ownership exceptions, trust flags or settings changed.
- [ ] Keep this PR draft until the issue-specific evidence is complete.

No merge, release or additional live workload is requested by this planning checkpoint. Existing evidence and dSYMs remain preserved. Use synthetic fixtures, bounded diagnostics and redacted public evidence; do not post credentials, personal paths or raw private reports.

## Current verification (2026-11-27)

- Installed Nick.app, active Endpoint Security extension and active network extension all report 5.1.6 / 5119.
- Strict blocking was observed ON and Emergency stop blocking OFF in Nick's existing settings. Neither setting was changed.
- The installed WhatsApp bundle verifies on disk and satisfies its designated requirement.
- A read-only Security-framework diagnostic using Nick's exact distribution requirement and current validation flags returned OSStatus 0. The diagnostic did not open credential files or collect their contents.
- The running app's signing identifier and team match `net.whatsapp.WhatsApp` / `57T9237FN3`; its image hash matches the current bundle, and kernel flags report valid, non-ad-hoc code. Process inspection was passive, without profiler attachment or suspension.
- The user quit and reopened WhatsApp and reported no new block. The process ID changed, and Nick's existing WhatsApp incident remained at 12 occurrences, last seen the previous day.

This is a bounded non-reproduction, not proof that the historical failure is fixed. It does not prove that the same credential file was opened during this launch, expose Nick's private validation-cache state, or cover update/cold-cache transitions. Do not add a WhatsApp allowlist or relax trust policy on this evidence.

## Regression coverage

Two focused tests exercise the exact sanitized container-cookie path. A validated main-app identity qualifies for existing own-store handling without requiring responsible-process attribution. The same strings without validation do not. An unrelated actor cannot inherit a responsible app's access; neighboring container identifiers and other apps' stores still produce findings.

Xcode UI run `Test-Nick-2026.11.27_12-40-02-+0300.xcresult`: all 39 `CredentialAccessPolicyTests` passed, zero failures, skips or runtime warnings. These are policy-model regressions, not a live unauthorized-reader trial.

No runtime source or enforcement behavior is changed by this PR. Keep #129 open for a fresh recurrence or stronger reproduction; do not close it as a newly shipped fix. The added coverage can be collected into the 5.1.7 integration branch after CI/review. No public release is authorized here.
