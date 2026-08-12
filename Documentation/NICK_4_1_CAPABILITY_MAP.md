# Nick 4.1 Runtime Compare Capability Map

This document is the implementation gate for Runtime Compare. It records what
Nick 4.1 reuses and where a comparison-specific adapter is required.

| Runtime Compare provider | Existing source | 4.1 adapter and boundary |
| --- | --- | --- |
| Processes | `ProcessScanner` | Snapshot immutable process evidence; normalize identity without PID. |
| Listeners and connections | `ConnectionScanner` | Split listeners from outbound flows and aggregate repeated observations. Never block traffic. |
| Persistence | `PersistenceWatcher` | Convert launch agents, daemons, login items, and related records to versioned evidence. |
| Endpoint Security health | `ExtensionXPCClient` | Record only whether Nick can verify the XPC sensor is responding. |
| Network filter health | `NetworkProtectionManager` | Record configured/provider health separately. A configured filter is not reported as running without a current provider heartbeat. |
| System and network extensions | macOS `systemextensionsctl list` read-only output | Parse category, bundle identifier, team identifier, version, activation, and enabled state. Parsing failure degrades only this provider. |
| Saved work | New bounded local store | Atomic JSON, schema-versioned, maximum 20 comparisons, explicit deletion. |
| Export | New support-bundle adapter | Sanitized Markdown and JSON previewed before a local ZIP is written. No upload destination. |

## Gaps deliberately left visible

- macOS does not provide Nick with a supported API that proves why an extension
  is stale or whether MDM intended a particular payload. Nick reports observed
  state and a cautious inference only.
- A bounded connection window cannot prove that an absent connection never
  occurred. Results use “not observed” language.
- Full process signing identifiers are not cheaply available for every process.
  Team ID and normalized path remain evidence-backed fallbacks.
- Nick 4.1 does not unload extensions, remove profiles, change filters, or alter
  MDM configuration.

## Failure contract

Every provider returns `available`, `partial`, or `unavailable` with an optional
human-readable reason. One provider failure never invalidates successful data
from the others. A cancelled capture is not saved as a completed snapshot.
