# Issue #129: Investigate WhatsApp own-cookie denial

Related issue: [#129](https://github.com/EhsanAzish80/Nick/issues/129)

## Current status

Draft work plan only. No runtime implementation, reproduction, fix or test pass is claimed by this commit. The original issue remains open. Base checkpoint: `171d1a8b3aea0c59628cae5817bc95d98c4b3951`.

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

- [ ] Confirm the current-build behavior with sanitized, issue-specific evidence.
- [ ] Add focused regression coverage for the demonstrated cause.
- [ ] Record positive and negative validation before marking this PR ready.

- [ ] Record the confirmed cause and resulting implementation in this document.
- [ ] Run relevant Xcode tests when implementation exists; do not label the planning commit as a tested fix.
- [ ] Review protection and detection impact, including negative cases where applicable.
- [ ] Keep this PR draft until the issue-specific evidence is complete.

No merge, release or additional live workload is requested by this planning checkpoint. Existing evidence and dSYMs remain preserved. Use synthetic fixtures, bounded diagnostics and redacted public evidence; do not post credentials, personal paths or raw private reports.
