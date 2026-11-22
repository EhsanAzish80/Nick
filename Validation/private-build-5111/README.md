# Private diagnostic build 5111 source checkpoint

This checkpoint preserves the source used for the already distributed signed and notarized 5.1.5 diagnostic build 5111. All 25 files in the build-time source manifest matched the retained snapshot and checkout before committing. The manifest is historical build-time evidence; installed validation has subsequently run. This checkpoint does not rebuild or publish a package.

Includes the measured credential-attribution storm and creation-history fixes, plus pending-AUTH, passive memory, scan-work and OS-report diagnostics. USB changes are counters only: no autorelease, scan-cap, mount-deduplication or scanning-policy fix. Trust policy is unchanged.

The external xcconfig records the private compilation condition used for the original archive. Matching dSYMs and binaries are retained locally with a post-commit provenance record keyed by this commit hash. No private download link, reporter diagnostics or signing credentials are stored here.

The original Xcode test run passed 1,056 tests. Installed checks and bounded local workloads do not establish resolution of the reporter’s multi-GB memory growth or deadline terminations. Issue #122 remains open. No release, merge, appcast or website update is part of this checkpoint.

The exact source checkpoint is commit `670159e6fc113e4292eee4b46c237d5490bd4a1c`. Subsequent PR cleanup represents file hashes as explicit path/SHA-256 records (same paths and digests), and moves the optional allocation helper’s future log directory to `/Library/Logs/NickAllocationLogging`. That helper edit is not part of the original installer and does not change the running 5111 binaries. The original build-time manifest remains in the local archive and checkpoint commit.
