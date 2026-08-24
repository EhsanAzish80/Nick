# Nick 4.5

Build 426 reduces noisy behavioral findings while preserving reviewable evidence and concrete malware detections.

## Detection accuracy

- Apple platform binaries without a conventional Team ID are trusted only when their signatures satisfy Apple's anchor requirement.
- Email attachment heuristics apply only to file formats capable of carrying the behavior described by each rule.
- SwiftPM artifact caches, XCFramework slices, scratch products, DerivedData, and verified repository builds are presented as development context instead of active threats.
- Download-to-shell alerts require evidence that a shell is executing an explicit command, rather than merely containing similar text in its arguments.
- Signed shell interpreters do not automatically make LaunchAgents safe.

## Protection status

- Overview and Smart Scan use the same fresh, version-matched Endpoint Security heartbeat.
- Real-Time Protection, Privacy Guard, Email Guard, and Ransomware Shield no longer depend on a transient XPC connection alone.
- Attention descriptions display their actual issue counts correctly.

## Verification

- 424 automated tests executed: 420 passed, 4 platform-dependent tests skipped, and 0 failed.
- Nick, NickExtension, NickNetFilter, and Nick Uninstaller all report version 4.5, build 426.
- An installed deep scan examined 96,555 files, produced no concrete threat verdicts, and reduced active review findings to two locally installed Zoom updater LaunchAgents.
- The Endpoint Security and Network Filter extensions were active at version 4.5 build 426 with a fresh health heartbeat.
- The installer package and disk image are Developer ID signed, notarized, stapled, and accepted by Gatekeeper.

## Requirements

- macOS 26 or later.
- User approval for the Endpoint Security and Network Extensions.
- Full Disk Access for Nick and NickExtension.
