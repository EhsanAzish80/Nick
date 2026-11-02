# Nick 5.1.0

Nick 5.1 strengthens local detection, signed protection updates and operational
reliability while keeping enforcement explicit and user controlled.

## Highlights

- Signed protection-intelligence updates with expiry, rollback protection,
  last-known-good recovery and visible update status.
- Broader credential, shell-pipeline, persistence, ransomware and transient
  file-change evidence with responsible-app attribution.
- A redesigned Settings experience with focused tabs in Simple and Advanced
  views, an Advanced search field and preserved approval flows.
- More durable Endpoint Security delivery and lower steady-state disk writes.
- Harmless signed canaries and installed replay tooling for transparent local
  validation without live malware.

## Protection controls

- Strict Mode is opt-in and remains off by default.
- Known-malware hash protection remains active independently.
- Emergency stop pauses supported blocking while detection and reporting stay
  active.
- Protection-reducing changes continue to require user authorization.

## Reliability and accuracy

- Endpoint Security callback handling no longer performs blocking process
  inspection on the response path.
- XPC reconnect and reply handling completes continuations exactly once.
- Continuity records distinguish expected replacement, ordinary restart and an
  unexpected protection gap.
- Routine installer, Apple maintenance, synchronization and atomic-replacement
  activity is classified more precisely.
- Incident rows use stable rule IDs, behavior-first titles, last-seen ordering
  and occurrence counts.

## Upgrading from 5.0

Install the signed package normally. macOS may briefly replace the system
extensions during the update. Existing settings and incident history are
preserved. Review Automatic protection updates and Strict Mode in Settings;
Strict Mode remains off unless you explicitly enable it.

## Known limitations

- Nick 5.1 does not claim the roadmap's 4/10 effectiveness target. Installed
  replay showed strong detection coverage, but broader prevention and
  detection-latency work remain planned for 5.1.1.
- Independent known-family corpus coverage and behavior-only effectiveness are
  not measured for this release.
- MDM management and compliance enforcement are not supported.
- An independent external security review is still pending.
