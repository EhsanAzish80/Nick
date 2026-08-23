# Nick 4.3

Build 421 fixes alert-state consistency and makes update checks reliable.

## Accurate attention state

- Resolved or reclassified alerts no longer leave a stale badge when the Active list is empty.
- Alerts whose file disappeared or whose process ended remain available in history without being counted as active threats.
- The menu bar status uses the same actionable, user-facing alert set as the Alerts view.

## Menu bar status

- The menu bar shield is green when protection is healthy, orange when something needs review, and red when immediate attention is required.
- The colored shield is rendered as a non-template image so macOS does not replace its state color with a black monochrome icon.

## Updates

- Automatic update checks are enabled on a daily schedule.
- Check for Updates now invokes Sparkle directly and records whether an update was found or the installed version is current.
- Existing Sparkle signing identity and package-based delivery remain unchanged for safe upgrades from earlier releases.

## Verification

- 373 automated tests executed: 369 passed, 4 platform-dependent tests skipped, and 0 failed.
- Nick, NickExtension, NickNetFilter, and Nick Uninstaller all report version 4.3, build 421.
- The installer package and disk image are Developer ID signed, notarized, stapled, and accepted by Gatekeeper.

## Requirements

- macOS 26 or later.
- User approval for the Endpoint Security and Network Extensions.
- Full Disk Access for Nick and NickExtension.
