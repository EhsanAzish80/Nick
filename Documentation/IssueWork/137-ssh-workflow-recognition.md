# Issue #137: SSH workflow recognition checkpoint

Related: #137. Original fallthrough condition is not established; keep the issue open for a synthetic-key installed check on the combined private build. No runtime exemption or trust-policy change in this PR.

## Source evidence

Current policies recognize exact Apple ssh-keygen Git signing/public-identity arguments and owned-key ssh-add arguments as observed, requiring non-root same-owner UID and validated identities. EventHandler already queues exit cleanup after credential classifiers, and ProcessTreeBoundsTests covers retaining a short-lived signing actor's arguments until observation completes. Captured parent identity is available when a parent exits. The exports' empty argument arrays are not proof of internal argument loss; they do not identify which recognition prerequisite failed.

Add negative coverage for missing argv, unsupported operations, wrong actor/Git identity, root or wrong owner, changed namespace and extra operands. Generic credential review remains the conservative fallback when command evidence is ambiguous. No real signing key was read for this checkpoint.

## Validation

- [x] Xcode UI full suite: 1,107 passed, zero failures/skips (2026-11-27 14:27 local).
- [x] New ambiguity tests and existing exact signing/agent and queued-exit regressions passed.
- [ ] Fresh PR CI passes.
- [ ] Combined private build: disposable-key Git signing and ssh-add; record which condition fails if review recurs.

The 13 existing main-thread warnings remain separate under #51. Full result and hashes: ignored `build/IssueValidation/137/`. This is regression coverage, not a claimed fix for the unexplained historical fallthrough. No main merge or public release.
