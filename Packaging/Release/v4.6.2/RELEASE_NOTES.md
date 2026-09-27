# Nick 4.6.2

Nick 4.6.2 introduces a simpler default experience while keeping every existing
security and diagnostic tool available in Advanced mode.

## Highlights

- A new Simple mode organizes Nick around Home, Scan, Activity, and Protection.
- Home shows one clear protection state, recent activity, and a Quick Check.
- Scan offers Quick Check, Full Scan, and focused file or drive scanning.
- Activity brings alerts, quarantined files, and blocked launches into one timeline.
- Protection explains each protection group and macOS security setting in plain language.
- Advanced mode keeps the complete Nick toolset and is always one switch away.

## Reliability improvements

- Deep Scan begins checking files while discovery is still running and continuously
  reports how many candidates have been found and checked.
- The menu bar icon now shows or hides Nick's main window in one click.
- Alert actions and explanations are clearer, with rule names, scores, and paths
  retained behind Technical Details.

## Verification

- The complete local macOS suite executed 490 tests: 486 passed, 4
  platform-dependent tests were skipped, and 0 failed.
- GitHub CI passed repository validation, YARA lint, the benign-corpus
  false-positive gate, shipping builds, and automated tests on the merged source.
- The SonarCloud Quality Gate and Codecov patch check passed on the release pull request.
- The PKG and DMG are Developer ID signed, notarized, stapled, and accepted by Gatekeeper.

Nick requires macOS 26 or later.
