# Issue #130: WhatsApp updater resource renames

Related: #130. Coverage and investigation checkpoint, not a new runtime fix. Keep the original issue open for a real updater transition on the combined private build.

## Current evidence

Current source already recognizes the report's nested `SharedModules.framework/Versions/A/Resources/BizModel.momd/.BC.T_*` to `.mom` finalization in a Sparkle installation slot. EventHandler requires kernel Apple-platform ditto and `validatedDistributionTeam` for the staged app. The exported alert provides actor/responsible identities but not the staged bundle validation result at that instant. A bundle still being copied may not pass validation; that is a hypothesis, not a demonstrated cause. Do not bypass signature validation based on process names or paths.

This PR adds the exact sanitized nested framework shape and negative tests, with no runtime exemption or trust-policy change. It cannot prove a historical update was safe or that a partial bundle was validated. The separate own-cookie issue #129 and sync issue #131 remain separate.

## Validation

- [x] Xcode UI: 24 RansomwareAtomicRenameTests passed, zero failures/skips/warnings (2026-11-27 14:16 local).
- [x] Exact staged framework shape accepted with validated team; missing/wrong validation, non-Apple actor, different slot, staging name, directory markers and malicious suffix rejected.
- [ ] Fresh PR CI passes.
- [ ] Capture a real benign updater transition on the combined private build; no forced app update or modification of installed WhatsApp performed here.

Full xcresult and hashes: ignored `build/IssueValidation/130/`. No main merge or public release.
