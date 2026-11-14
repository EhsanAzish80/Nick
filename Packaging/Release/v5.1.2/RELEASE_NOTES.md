# Nick 5.1.2 — quieter maintenance alerts and clearer recovery

Release: **5.1.2 (5103)** for macOS 26 and later.

Download the signed and notarized installer package, or the notarized disk image containing the same installer. Existing installations can use Check for Updates once the website feed is deployed.

## Fixed

- Recognize validated Chrome profile ownership, including containing-app helpers, without allowing cross-app credential-store access.
- Keep the exact validated GoogleUpdater command that removes quarantine metadata from Chrome informational.
- Distinguish expected restart recovery from runtime interruptions, preserve original gap timestamps, and remove misleading malware language from recovery events.
- Reduce maintenance rename false alerts for scoped iCloud/File Provider staging, installer icons, GeoServices, simulator resources and WhatsApp updates. Identity and paired paths remain required.
- Validate nested Loom executable provenance against the observed code hash before warning.
- Preserve verified Git public-key derivation context and show the affected client in permission-change events.

## Validation and limits

The final source passed 1,003 Swift tests; 52 Python tests passed earlier in this patch cycle. Both installer and disk image passed Apple notarization, staple validation and Gatekeeper checks. The user reported successful focused checks on a Mac Studio and M1 MacBook Pro, including Chrome, Claude, Loom, iCloud syncing and restart recovery; the GoogleUpdater correction was confirmed on 5103.

Six synthetic prevention cases were previously measured on 5101. They were not replayed on 5103 and are not claimed as new 5103 measurements. No additional soak or scorecard run was performed. Strict blocking remains opt-in and network monitoring remains observation-only. Independent effectiveness and extension deadline/latency measurements remain open; the original cause of a retained extension interruption is unconfirmed.
