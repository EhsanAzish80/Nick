# Nick 4.6.3

Nick 4.6.3 is a security and reliability update focused on the boundary between
the app and its Endpoint Security extension, safer quarantine restoration, and
more private local diagnostics.

## Highlights

- Requires Nick's exact signed app identity for internal communication with the
  Endpoint Security extension.
- Protects persisted endpoint events while keeping component health available
  to the app.
- Makes quarantine restoration resistant to redirected paths and restores files
  with safe ownership and permission handling.
- Removes an unused privileged file-scan path.
- Reduces sensitive process information written to diagnostic logs.
- Reports missing internal communication configuration through Smart Scan.

## Verification

- GitHub CI passed repository validation, YARA lint, the benign-corpus
  false-positive gate, application and shipping-component builds, and tests.
- The complete local macOS suite executed 497 tests: 493 passed, 4
  platform-dependent tests were skipped, and 0 failed.
- The SonarCloud Quality Gate and Codecov patch check passed on the release pull
  request.
- The PKG and DMG are Developer ID signed, notarized, stapled, and accepted by
  Gatekeeper.

Nick requires macOS 26 or later.
