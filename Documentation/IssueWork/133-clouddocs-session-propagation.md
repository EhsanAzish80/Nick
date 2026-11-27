# Issue #133: CloudDocs session propagation

Related: #133. Installed verification remains pending on the combined private build.

The existing bird staging-to-session matcher recognizes pcm/flat/meta but omitted the reported dia resource. Add dia only within that existing exact relation: Apple-platform `com.apple.bird`, UUID FileProvider provider, numeric wharf propagation slot and same-user direct `CloudDocs/session/i` destination. No blanket bird, iCloud or dia exemption. Existing generic CloudDocs map/meta behavior is unchanged.

## Validation

- [x] Xcode UI: 24 RansomwareAtomicRenameTests passed; zero failures/skips/warnings (2026-11-27 14:15 local).
- [x] Negative actor/platform, provider/slot, user, nested/wrong session directory, Documents and `.locked` cases.
- [x] Existing ransomware burst regressions passed; live home canaries and non-staging mutations remain outside this match.
- [ ] Fresh PR CI passes.
- [ ] Combined private-build CloudDocs sync/protection check.

Evidence: ignored `build/IssueValidation/133/` contains full xcresult and hashes. Synthetic paths only; no user files changed. No main merge or public release.
