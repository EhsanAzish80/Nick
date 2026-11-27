# Issue #140: XCTest SpringBoard cache finalization

Related: #140. Installed verification remains pending on the combined private build.

## Confirmed gap

The paired SpringBoard temp-to-MappedImageCache matcher accepted CoreSimulator device roots only. XCTest uses `Library/Developer/XCTestDevices/<UUID>/data`. Recognize this alternate root for SpringBoard only, preserving the same-user/device boundary, matching temporary basename, `cpbitmap` destination and exact cache prefix. The kernel Apple-platform requirement and exact signing ID remain unchanged. MobileAsset does not inherit the XCTest alternative.

No general simulator, Apple process or extension exemption. Cross-device/user destinations, spoofed identities, unrelated temporary files, Documents and `.locked` destinations remain outside the exception. UI-stall causality is tracked separately in #139. The repeated JSON exports had identical IDs and do not establish duplicate incidents.

## Validation

- [x] Xcode UI: 24 RansomwareAtomicRenameTests passed, zero failures/skips/warnings (2026-11-27 14:09 local).
- [x] New paired-scope regression includes identity, device, name and destination negatives.
- [x] Existing CoreSimulator and ransomware burst tests passed.
- [ ] Fresh PR CI passes.
- [ ] Combined private build: XCTest launch/cache operations and unrelated protection checks.

Full local xcresult and hashes: ignored `build/IssueValidation/140/`. No real simulator data changed, no main merge or public release.
