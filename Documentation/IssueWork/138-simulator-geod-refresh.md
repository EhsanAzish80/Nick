# Issue #138: Simulator GeoServices resource refresh

Related: #138. Installed verification remains pending on the combined private build.

## Confirmed gap and change

The host GeoServices matcher expects `Library/Containers/com.apple.geod/Data/tmp/<UUID>`. The reported simulator uses `Library/Developer/CoreSimulator/Devices/<UUID>/data/tmp/<UUID>`, which did not match. Recognize only that same-user, same-device temporary resource finalization into the exact GeoServices cache folder: `styl` in Resources, or `iconconfigpack`/`icondatapack` in RegionalResources.

The existing kernel Apple-platform check and exact `com.apple.geod` signing ID remain required. No new trust-policy or filesystem work was added. Host behavior is unchanged. This is not a process, simulator-directory or suffix-wide exemption. Cross-device/user moves, unrelated sources/destinations, invalid UUIDs, nested cache folders and `.locked` destinations remain outside the exception. Live home canary paths are disjoint from this UUID staging shape; unrelated ransomware behavior remains subject to existing evaluation.

## Validation

- [x] Synthetic positive paths cover each supported resource kind, including the reported icon pack shape.
- [x] Negative cases cover identity, user/device, staging and destination boundaries.
- [x] Xcode UI: RansomwareAtomicRenameTests, 25 passed, zero failed/skipped or runtime warnings (2026-11-27 14:07 local).
- [x] Existing host, atomic-save and ransomware burst regressions in that class passed.
- [ ] Fresh PR CI passes.
- [ ] Combined private build: simulator resource refresh stays quiet and unrelated ransomware behavior remains protected.

Evidence: local ignored `build/IssueValidation/138/`; no simulator data was changed. No public release or main merge.
