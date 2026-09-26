# Nick 4.6.1

Nick 4.6.1 is a focused reliability update for Deep Scan and the built-in
updater.

## Fixes

- Deep Scan immediately shows that it is indexing files before measurable scan
  progress is available.
- Scan progress remains responsive while multiple YARA workers finish files.
- Check for Updates now reports whether Nick is checking, already current, has
  an update available, or encountered an error.
- Settings displays the installed app version correctly.

## Verification

- GitHub CI, the benign-corpus YARA gate, Codecov, and the SonarCloud Quality
  Gate passed on the release source.
- Deep Scanner lifecycle tests cover the immediate indexing state.
- The complete macOS suite executed 443 tests: 439 passed, 4
  platform-dependent tests were skipped, and 0 failed.

Nick requires macOS 26 or later.
