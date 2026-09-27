# GitHub contributor roadmap

## Contribution funnel

1. README explains Simple vs Advanced and sets honest product scope.
2. `CONTRIBUTING.md` routes bugs, false positives, rules, code, and docs.
3. Issue forms collect reproducible evidence without secrets or live malware.
4. `good first issue` work stays documentation-, test-, or UI-bounded.
5. `help wanted` work includes maintainer context and explicit acceptance tests.
6. Security vulnerabilities remain private through `SECURITY.md`.

## First five contributor-friendly issues

### 1. Document a safe false-positive fixture cookbook

- Labels: `documentation`, `good first issue`, `false-positive`
- Scope: add examples for signed updater, SwiftPM/XCFramework artifact, Homebrew
  wrapper, and ordinary document attachment fixtures.
- Acceptance: no live malware; every example states expected verdict and the
  focused test command; repository validation passes.

### 2. Add accessibility identifiers to Simple Scan actions

- Labels: `accessibility`, `good first issue`, `swiftui`
- Scope: Quick Check, Full Scan, file/drive chooser, cancel, and result actions.
- Acceptance: stable identifiers, no visible copy changes, focused UI test or
  documented Accessibility Inspector proof.

### 3. Explain bundled YARA rule provenance in generated documentation

- Labels: `documentation`, `yara`, `help wanted`
- Scope: produce a table of rule file, author, reference, class, and severity
  from validated metadata.
- Acceptance: deterministic generation; missing required metadata fails; no
  network fetch during build.

### 4. Add negative tests for signed updater LaunchAgents

- Labels: `tests`, `false-positive`, `good first issue`
- Scope: representative Zoom-style and other signed updater plist arguments.
- Acceptance: benign signed updater context remains review-only or suppressed
  according to policy; unsigned lookalike stays actionable; no hardcoded local path.

### 5. Improve Deep Scan cancellation diagnostics

- Labels: `swift`, `help wanted`, `scanning`
- Scope: expose a sanitized final state distinguishing user cancellation from
  read/permission failures.
- Acceptance: lifecycle tests cover cancel during discovery and active workers;
  no result mutation after cancellation; UI remains responsive.

## Maintainer preparation before publishing issues

- Confirm each issue is still unsolved on `main`.
- Add exact source files and a focused test command.
- Reserve security-sensitive policy changes for maintainer-led work.
- Create `good first issue`, `help wanted`, `documentation`, `tests`,
  `false-positive`, `accessibility`, `swiftui`, `yara`, and `scanning` labels if
  absent.
- Publish no more than five prepared issues initially; respond within two
  working days when someone volunteers.

## Contributor measures

- Unique issue commenters and first-time contributors.
- Issues with enough evidence to reproduce on first review.
- Time to first maintainer response.
- External pull requests opened, merged, or closed with a documented reason.
- Negative-fixture coverage added—not raw issue count.

