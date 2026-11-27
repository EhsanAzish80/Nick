# Issue #51: Main-thread signature inspection

Related: #51. Source fix validated locally; installed warning validation remains pending. The historical issue stays open.

## Concrete blocking path found

MainActor ExtensionXPCClient.receiveThreat constructs ExtensionFinding synchronously. For exec-target or missing-kernel-team evidence, its initializer calls SignatureValidator.evaluate, which performs file identity work and Security-framework inspection on a cache miss. The ordinary receive(event:) path constructs the same finding synchronously. This is concrete main-thread disk/Security work. The historical warning alone does not prove this was the source of every five-minute warning or all reported UI stalls.

The current edit routes both production event paths through a dedicated serial signature-work queue; the existing MainActor finding handler and durability boundary still await the resolved finding. Signature requirements, result classification and endpoint enforcement are unchanged. The synchronous constructor remains available for controlled tests.

## Pending validation

- [x] Xcode UI: all 31 ExtensionXPCClientIncidentTests passed (2026-11-27 14:50 local), including off-main resolver, MainActor responsiveness under blocked work and equivalent evidence fields.
- [x] Existing ingest/persistence regressions in that class passed. A preceding full run passed 1,107 tests with one incomplete synthetic fixture failure; the corrected fixture passed in the class rerun. Final integrated full suite remains required.
- [x] Both production event constructors use the asynchronous path.
- [ ] Fresh CI passes on the tested commit.
- [ ] Combined private build: bounded Diagnostics refresh and normal ingestion, checking warning output.

Four tests in the focused run still emit the old warning while directly using the synchronous constructor. Do not claim those warnings or the historical root cause are resolved without evidence. No new soak, profiler attachment, settings change, main merge or public release.

Full result and hashes: ignored `build/IssueValidation/51/`. No protection or trust-policy changes.
