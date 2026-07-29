# Nick 4.0.1

Nick 4.0.1 is a safety and reliability update for Nick 4.

- Trusted applications no longer create permanent security blind spots.
- “Always Allow” is limited to the same signed executable and behavior context,
  expires after seven days, and does not cover new behavior.
- Malware matches, persistence changes, reverse shells, system-security changes,
  and other critical evidence always alert, even for a previously approved app.
- Familiar developer tools such as Xcode and Visual Studio Code can no longer
  bypass strong detections merely because their names are trusted.
- Endpoint Security process authorization fails open so Nick does not interrupt
  Xcode builds, AirDrop, Handoff, Universal Clipboard, or normal app launches.
- Heuristic YARA matches are reported for review instead of automatically
  blocking or quarantining files. Exact known-malware hashes retain enforcement.
- Scam Guardian is shown as active only when the Network Filter is enabled and
  its provider is reporting a current live heartbeat.
- The dashboard and Smart Scan now use the same verified Scam Guardian state.
- Alert actions include one-time acceptance, context-limited approval, blocking,
  and quarantine where those actions are safe and applicable.

Nick 4.0.1 requires macOS 26 or later.
