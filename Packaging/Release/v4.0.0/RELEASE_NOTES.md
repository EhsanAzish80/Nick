# Nick 4.0

Nick 4.0 adds active network protection alongside the existing Endpoint
Security engine.

- Guided setup verifies each required macOS approval instead of assuming it is active.
- Scam Guardian blocks known phishing and lookalike domains.
- Email Guard performs day-one attachment scanning with updated YARA rules.
- Alerts identify detected files and rules, explain where they were found, and
  safely re-scan confirmed threats before moving them to Quarantine.
- Nick no longer flags its own Xcode build artifacts, and medium-confidence
  YARA behavior rules are presented for review instead of as confirmed malware.
- Threat Timeline shows Endpoint Security activity without false inactive states.
- Performance cleanup has a redesigned interface and safer recommendations.
- Nick Uninstaller removes the app, extensions, configuration, and generated data.
- Background monitoring and UI refresh work have been reduced for better performance.

Nick 4.0 requires macOS 26 or later.
