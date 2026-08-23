# Nick 4.4

Build 422 improves detection accuracy, scan continuity, and the explanations shown when Nick asks for attention.

## Deep Scan

- Deep Scan continues while you move between sections of Nick.
- Findings distinguish concrete malware signatures from behavior that needs context and review.
- Canonical paths and rule identities prevent duplicate findings.
- Application caches, developer repositories, and verified Homebrew layouts receive appropriate context without hiding concrete or critical signatures.
- Scan progress, cancellation, and result publication remain consistent throughout a run.

## Processes and network activity

- Process signing and threat columns now resolve live evidence and distinguish checking, unavailable, clean, and suspicious states.
- Network Activity explains the responsible app, destination type, port, and observation reason.
- Allow actions state whether they apply to one destination or to the responsible app.

## Alerts and attention state

- Overview identifies the specific issue that needs attention and links directly to the relevant evidence.
- Alerts distinguish observations, historical evidence, missing files, and actionable threats.
- Trusted or ignored context can reduce only non-critical behavioral noise; concrete signatures and critical evidence remain visible.

## Verification

- 406 automated tests executed: 402 passed, 4 platform-dependent tests skipped, and 0 failed.
- Nick, NickExtension, NickNetFilter, and Nick Uninstaller all report version 4.4, build 422.
- The installer package and disk image are Developer ID signed, notarized, stapled, and accepted by Gatekeeper.

## Requirements

- macOS 26 or later.
- User approval for the Endpoint Security and Network Extensions.
- Full Disk Access for Nick and NickExtension.
