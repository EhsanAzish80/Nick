# Nick 5.0

Nick 5.0 introduces a simpler everyday experience alongside the full Advanced
interface, with clearer protection status, safer remediation, and more useful
incident context.

## Highlights

- New Simple mode for Home, Activity, Protection, Scan, and Storage.
- One consistent protection status and actionable count across Simple Home,
  Activity, Advanced Overview, Smart Scan, and System Audit.
- Clear incident states: Needs review, Blocked, Quarantined, Remediation
  needed, Resolved, and informational Observed.
- Responsible-app attribution for behavior detections, including bounded helper
  and command chains.
- More precise download-to-shell and ransomware-behavior detections, reducing
  false positives from ordinary developer workflows.
- Safer remediation: behavior-only findings and protected system executables
  never offer file quarantine or Move to Trash.
- Validated self-exclusion when scanning Nick's own signed app bundle.
- Improved failed-remediation explanations and separate controls for clearing
  incident history and learned decisions.
- Storage review in both interface modes, with an optional link to JunkYard
  Cleaner for deeper storage work.

## Verification

- GitHub build-and-test and SonarCloud checks passed for the final attribution
  change.
- The complete local suite executed 789 tests: 785 passed, 4
  platform-dependent tests were skipped, and 0 failed.
- Build 5052 was validated live with the app, Endpoint Security extension, and
  Network Filter extension active at the same build number.
- The final responsible-app attribution fixture produced the complete app to
  helper to shell chain and returned to Protected after review.
- The release PKG is Developer ID signed, notarized, stapled, and accepted for
  distribution.

Nick requires macOS 26 or later.
