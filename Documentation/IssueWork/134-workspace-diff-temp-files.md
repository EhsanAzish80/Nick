# Issue #134: Temporary output is not payload execution

Related: #134. Installed validation remains pending on the combined private build.

## Confirmed cause and change

Both the app detector and shared Endpoint Security policy accepted `mktemp` plus `&&`, `;` or `$(` as execution evidence. Ordinary command substitution and diff output therefore claimed payload execution without an invocation. Both now use one syntax recognizer: track a variable assigned a mktemp substitution, then require a command-position invocation, interpreter file operand, or dot/source operation referring to that exact result. Direct interpreter invocation of a mktemp substitution also qualifies. Assignment overwrite removes the tracked association. Quoted literals, comments, redirection and read-only file operands do not qualify by themselves.

This is syntax evidence, not a full shell interpreter or proof a branch executed. Aliases, dynamically constructed commands and arbitrary shell expansion are outside its recognition; they are not globally marked safe. Independent download-to-shell, encoded execution, provenance and runtime monitoring are unchanged. No Codex, bash, mktemp or signer exemption was added. No command from a fixture was executed; all are strings evaluated by the policies.

## Validation

- [x] Xcode UI full suite: 1,107 passed, zero failed/skipped (2026-11-27 14:21 local).
- [x] Benign command substitution, diff output/error/Git index, comments, quoted examples and overwritten variables; direct, interpreter and sourcing positives.
- [x] App detector uses the shared recognition rule, tested with benign and malicious examples.
- [x] Existing detection tests passed. The 13 pre-existing main-thread runtime warnings remain tracked separately under #51; they are not claimed fixed here.
- [ ] Fresh PR CI passes.
- [ ] Combined private-build benign shell workflow check.

Full xcresult and hashes: ignored `build/IssueValidation/134/`. Earlier cancelled/failed test builds are not counted as passes. No main merge or public release.
