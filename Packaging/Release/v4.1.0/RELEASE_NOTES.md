# Nick 4.1

Build 416 adds Runtime Compare and Network Diagnostics to Nick.

## Runtime Compare

- Capture local before-and-after runtime snapshots for processes, persistence,
  listening ports, connections, system extensions, and sensor health.
- Resume a comparison after restarting the same Mac.
- Review deterministic findings with evidence quality and visibility limits.
- Preview and export sanitized Markdown and JSON support bundles.

## Accuracy and safety

- Cross-restart process churn is excluded from findings.
- Active system-extension records take precedence over retiring generations.
- Missing provider evidence creates a visibility warning rather than
  unsupported added or removed findings.
- Snapshot, import, retention, observation, and event limits keep collection
  local and bounded.
- Runtime Compare is diagnostic and read-only. It does not remediate MDM state,
  enforce compliance, collect fleet data, or block network traffic.

## Verification

- 349 automated tests executed: 345 passed, 4 platform-dependent tests skipped,
  and 0 failed.
- A real baseline, restart, and follow-up comparison completed without the
  former process flood or false Nick extension transitions.
- Both release artifacts are signed, notarized, stapled, and accepted by
  Gatekeeper.

## Requirements

- macOS 26 or later.
- User approval for the Endpoint Security and Network Extensions.
- Full Disk Access for Nick and NickExtension.
