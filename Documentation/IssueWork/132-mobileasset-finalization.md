# Issue #132: Host MobileAsset finalization

Related: #132. Installed verification remains pending on the combined private build.

## Confirmed gap and change

The existing matcher covers simulator MobileAsset staging only. The report uses the host `/System/Library/AssetsV2/staging/<type>.<hash>` to `/System/Library/AssetsV2/<type>/<hash>.asset` shape. Recognize only this direct staging-to-final relation, with an identical nonempty MobileAsset type and 40-hex hash. The existing kernel Apple-platform check and exact `com.apple.mobileassetd` signing ID remain required.

No broad MobileAsset, AssetsV2 or `.asset` exemption. No file/directory type is inferred from the export; this rule checks the paired rename metadata, not file contents. Existing simulator behavior is unchanged. User documents, mismatched types/hashes, nested paths and ransomware suffixes do not match. No new filesystem or trust-policy work.

## Validation

- [x] Xcode UI: 24 RansomwareAtomicRenameTests passed; zero failures/skips/warnings (2026-11-27 14:13 local).
- [x] Reported type/hash pattern and negative identity, root, nested, mismatch, malformed hash and `.locked` cases.
- [x] Existing simulator and ransomware burst regressions passed.
- [ ] Fresh PR CI passes.
- [ ] Combined private-build MobileAsset/protection checks.

Local full result and hashes: ignored `build/IssueValidation/132/`. Synthetic paths only. No main merge or public release.
