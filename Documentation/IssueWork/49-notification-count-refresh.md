# Issue #49: Refresh delivered counts after persistence

Related: #49. Installed Notification Center validation remains pending on the combined private build.

## Confirmed gap and change

The incident store correctly coalesces protected occurrences inside the 600-second banner throttle, but only newly actionable alerts were staged for post-persistence delivery. Add a separate refresh list and generation queue. Confirmation releases the newest whole-incident snapshot; a new banner for the same ID takes priority. Silent refreshes do not reset lastNotifiedAt or invoke other alert outputs.

NotificationManager queries already-delivered entries and only replaces an existing canonical ID. Removed notifications are not intentionally recreated. The replacement has no sound, passive interruption level and an explicit foreground suppression marker. It preserves the canonical ID and updates the occurrence count. A serial refresh loop coalesces newer pending counts, rejects stale/equal delivered counts and bounds pending incident IDs to 100. Normal urgent notification behavior and the 10-minute reminder remain unchanged.

## Validation

- [x] Xcode UI: 30 IncidentStorePersistenceTests passed; zero failures/skips/warnings (2026-11-27 14:53 local).
- [x] Reproduce 4 to 6 occurrences within throttle: no newly actionable banner, stable incident ID, unchanged notification timestamp; release only after generation confirmation and only once.
- [x] Request has updated count, same ID, no sound, passive priority and empty foreground presentation options; equal counts and unrelated IDs rejected.
- [x] Reminder after the throttle still becomes newly actionable.
- [ ] Fresh CI passes.
- [ ] Combined private-build Notification Center check confirms macOS list replacement and absence of a new banner/sound.

No real system notification was sent by the regressions. Full xcresult and hashes: ignored `build/IssueValidation/49/`. No protection policy change, main merge or public release.
