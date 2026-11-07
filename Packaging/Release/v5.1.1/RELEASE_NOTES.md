# Nick 5.1.1 — clearer alerts and more reliable reporting

Release candidate: build 5101. Publication pending.

- Reduce false alerts for validated app updates, iCloud/File Provider staging, GeoServices cache refreshes and Codex session compression, using scoped identity and path checks.
- Preserve short-lived Git/SSH signing context and allow Nick's validated scanner to inspect browser stores without blocking itself.
- Prevent special-file prefix reads from blocking the extension's serial reporting queue.
- Improve reviewed/blocked activity, rename-denial wording, first-run documentation and Clear History confirmation.
- Make menu-bar clicks consistently bring Nick forward.
- Improve deep-scan handling of validated nested application code while retaining actionable malware findings.

## Validation

995 Swift tests and 52 Python tests passed. The notarized installer passed stapling, Gatekeeper and release-payload YARA checks (11 executables, zero matches).
Installed 5101 recorded prevention for the six synthetic EICAR, Keychain-copy, browser-login, SSH-key, tamper and ransomware fixtures, with observation bounds of 0.60–1.41 seconds. This is selected-fixture validation, not a general malware-effectiveness rating.

## Boundaries

Strict Mode is opt-in. Network monitoring remains observation-only. No complete detection or 4/10 effectiveness claim is made. User reported a quiet 24-hour normal-use observation on 5097, but its later reporting stall limits that evidence. Build 5100 recorded 21/24 detections with all mandatory families; 5101 received focused installed validation of six prevention cases and permission-fixture lineage after the final persistence correction. Earlier-build detection results are not represented as 5101 measurements. Independent corpus and ES health targets remain unmeasured. No additional soak is required.
