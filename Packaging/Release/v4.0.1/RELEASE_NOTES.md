# Nick 4.0.1

Build 408 is a safety and reliability update for Nick 4.

## Network safety

- Scam Guardian now operates in observation-only mode.
- Suspected phishing and lookalike destinations remain visible for review.
- The Network Filter contains no traffic-drop verdict path and cannot
  interrupt ordinary application connections.
- Missing, stale, or invalid Network Filter configuration fails open.
- Browsers, Git, developer tools, AirDrop, Handoff, and other legitimate
  services continue to connect while Scam Guardian observes destinations.

## Protection status

- Smart Scan and setup distinguish destination monitoring from active
  blocking.
- Endpoint Security and Network Extension health still require current runtime
  confirmation before Nick reports them as active.
- Full Disk Access remains required for NickExtension, Endpoint Security, and
  Email Guard.

## Verification

- 321 automated tests passed and 4 platform-dependent tests were skipped.
- The package and disk image are signed with Developer ID, notarized, stapled,
  and accepted by Gatekeeper.
- A controlled runtime check confirmed GitHub web and Git remote access with
  both system extensions enabled.

## Requirements

- macOS 26 or later.
- User approval for the Endpoint Security and Network Extensions.
- Full Disk Access for Nick and NickExtension.
