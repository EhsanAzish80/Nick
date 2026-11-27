# Issue #131: FileProvider encrypted backup propagation

Related: #131. Installed verification remains pending on the combined private build.

The existing policy recognizes `ExtChatDatabase.sqlite.enc`; the reported file is `BackedUpStorageDatabase.sqlite.enc`. Add only that exact name to the existing backup filename set. Keep Apple-platform `com.apple.fileproviderd`, numeric FileProvider propagation slot, UUID provider, same user, exact WhatsApp container, numeric account and direct backup directory requirements.

No generic `.enc`, iCloud, WhatsApp or Apple exemption. Synthetic negatives include other containers, users, account names, nested directories, arbitrary encrypted documents and `.locked` destinations. Real home canaries and non-staging encryption do not match this shape.

## Validation

- [x] Xcode UI: 24 RansomwareAtomicRenameTests passed; zero failures/skips/warnings (2026-11-27 14:11 local).
- [x] Both exact backup filenames and negative scope/identity cases covered; existing ransomware burst regressions passed.
- [ ] Fresh PR CI passes.
- [ ] Combined private build: WhatsApp backup sync and unrelated protection checks.

Local full xcresult and hashes: ignored `build/IssueValidation/131/`. Synthetic paths only; no real backup data modified. No main merge or public release.
