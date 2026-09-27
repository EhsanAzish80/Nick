# Nick 4.1 Runtime Snapshot Schema

Runtime snapshots use schema version `1`. Raw records are immutable evidence;
stable identity keys are computed for comparison and are not stored as claims.

## Envelope

- Snapshot UUID, schema version, label, scenario, start/end timestamps.
- Nick version, macOS version, architecture, installation-scoped device token,
  and boot-session identifier.
- Requested and actual observation duration.
- Provider health and completeness.

## Records

- Process: PID evidence, name, path, parent evidence, user, start time, signing
  state, and team ID when available.
- Listener: protocol, local address/port, owner name/path, and PID evidence.
- Connection: protocol, remote address/port, owner name/path, first/last seen,
  and observation count. Local ephemeral ports are not identity.
- Persistence: type, scope, name, source path, executable path, enabled state,
  signing state, and modification time.
- Extension: category, bundle/team identifier, version, activation/enabled
  state, and containing app when observable.
- Sensor health: Endpoint Security XPC, Network Filter provider, and provider
  capture results.

## Stable keys

1. Process: signing identifier plus team ID; otherwise team ID plus normalized
   path; otherwise normalized path; name is a weak final fallback.
2. Listener: protocol, normalized address scope, port, stable owner.
3. Connection: stable owner, protocol, normalized remote destination, remote
   port. PID and local ephemeral port are ignored.
4. Persistence: type, scope, normalized source path, label.
5. Extension: category, team ID, bundle ID.

## Finding contract

Every finding contains a category, change kind, evidence level, attention
level, title, explanation, limitation, and source-record references. Findings
must distinguish observed facts from inferences and from facts Nick cannot
confirm.

## Privacy and compatibility

Local snapshots remain original. Sanitization creates an export copy and
deterministically replaces usernames, home paths, local/remote addresses, and
other device-specific values within that export. Unknown future schema versions
must be rejected with a clear compatibility error rather than decoded loosely.
