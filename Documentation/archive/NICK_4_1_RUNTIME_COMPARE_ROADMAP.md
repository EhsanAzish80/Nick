# Nick 4.1 Design and Acceptance Record: Runtime Compare and Network Diagnostics

Status: approved product and technical roadmap. Implementation and release
readiness remain subject to the gates in this document.

This document records the decisions agreed before implementation so that Nick
This document was the implementation roadmap for Nick 4.1 and is retained as
the design and acceptance record for build 416. It defined the product before
implementation so 4.1 could be built without changing direction midway. Any
material scope, schema, privacy, or product-language change should update this
document before code is changed.

Companion design references:

- [Runtime Compare capability map](NICK_4_1_CAPABILITY_MAP.md)
- [Runtime snapshot schema](NICK_4_1_SNAPSHOT_SCHEMA.md)

## Release outcome

Nick 4.1 will let a Mac administrator capture the machine's runtime state
before and after a security, MDM, VPN, EDR, application, or network-policy
change, then receive a concise and explainable report of what changed.

Primary promise:

> Capture, compare, and explain changes to processes, persistence, listeners,
> outbound connections, and Apple system and network extensions without
> blocking traffic or claiming to enforce a compliance baseline.

Nick remains a local observation and investigation tool. It does not replace
MDM, mSCP, an EDR, a firewall, or a compliance assessment.

## Product boundaries

### Included in 4.1

- One labeled baseline and one labeled follow-up capture per comparison.
- Processes, persistence, listeners, outbound connections, system extensions,
  network extensions, and sensor health.
- A deterministic, normalized comparison with evidence drill-down.
- Guided scenarios for security or MDM changes, VPN or network problems,
  application installation or removal, and custom comparisons.
- Explicit visibility and permission limitations.
- Local saved comparisons with bounded retention and deletion controls.
- Sanitized Markdown and JSON support bundles with an exact preview.
- Import and re-comparison after reboot on the same Mac when device identity
  can be verified.
- Observation-only, fail-open network behavior.

### Explicitly excluded from 4.1

- CIS or mSCP compliance certification.
- Automatic hardening, repair, remediation, profile removal, or extension
  unloading.
- Network blocking or traffic enforcement.
- MDM server, Intune, Jamf, or Kandji API integration.
- Fleet collection or a headless managed collector.
- Cross-Mac compliance comparison.
- Packet contents, TLS interception, browser history, or document contents.
- Definite claims that a component is stale, orphaned, malicious, or the cause
  of an outage when the captured evidence cannot prove that conclusion.
- HTTP upload, CEF delivery, or other remote export destinations unless a
  separately reviewed existing pipeline can meet all privacy and reliability
  requirements without expanding the release scope.

## Information architecture

Runtime Compare receives its own sidebar destination because it combines
multiple sensors in a user-initiated workflow rather than representing a live
monitor or malware scan.

```text
Overview
Smart Scan

SECURITY
Alerts
Scan
Quarantine

MONITORS
System Audit
Network
Processes
Persistence

DIAGNOSTICS
Runtime Compare
Performance

Settings
```

The sidebar label is **Runtime Compare**. The section label is
**Diagnostics**. The word "baseline" may be used inside the workflow, but the
primary product language emphasizes comparison rather than compliance.

The existing Network, Processes, and Persistence views remain live/current
state views. They may later include a "Compare this state" entry point, but
those links must open the same Runtime Compare workflow rather than create
parallel implementations.

## Landing screen

The landing view explains the outcome and shows saved work.

```text
Runtime Compare

See what changed after installing, removing, or reconfiguring
security, VPN, MDM, and network software.

[ Start a comparison ]

Recent comparisons
┌─────────────────────────────────────────────────────────┐
│ Intune migration                         Completed today │
│ 4 important changes · 12 other changes                 │
│ Before migration → After migration                     │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ VPN troubleshooting                        In progress  │
│ Baseline captured · Follow-up needed                    │
│ [ Continue ]                                            │
└─────────────────────────────────────────────────────────┘
```

The empty state must explain why a comparison is useful; it must not be an
empty table.

## Guided comparison workflow

### Step 1: Choose a scenario

The user chooses one of four scenarios:

1. **Security or MDM change** — compare runtime behavior before and after a
   management or hardening change.
2. **VPN or network problem** — emphasize extensions, listeners, DNS/network
   components, and connections.
3. **App installation or removal** — show processes, background items,
   listeners, and extensions added or removed by an application change.
4. **Custom comparison** — capture and label any before/after state.

Scenarios affect ordering, emphasis, examples, and explanation templates. They
do not create separate schemas, collectors, or comparison engines.

### Step 2: Name the comparison

The scenario and user label are stored separately. Suggested labels include:

- Before and after Intune migration
- VPN enabled versus disabled
- Before and after installing an EDR
- Normal boot versus Safe Mode

### Step 3: Capture the baseline

The capture view exposes progress by provider and distinguishes static state
from transient observation.

```text
Capturing "Before Intune migration"

✓ Processes
✓ Persistence
✓ Listening ports
● Observing connections — 18 seconds remaining
✓ System and network extensions
✓ Sensor and permission health

[ Cancel ]
```

- Processes, persistence, listeners, extensions, and sensor health are
  point-in-time state.
- Connections and short-lived activity use a visible, bounded observation
  window.
- The default connection observation window is 30 seconds.
- Advanced choices may offer 30 seconds, 1 minute, and 5 minutes.
- Nick must describe this as observing runtime activity, not scanning for
  malware.
- Cancellation must be safe and leave no half-valid snapshot presented as
  complete.

After a successful baseline, Nick tells the user to make the external change
and permits the workflow to be closed and resumed later.

### Step 4: Capture the follow-up

The follow-up uses the baseline collection configuration where possible. Nick
records and visibly reports differences that weaken comparison quality,
including:

- Different connection-observation duration.
- Endpoint Security available for only one capture.
- Network Extension unavailable for one capture.
- Full Disk Access or other permission differences.
- Dropped events or collection failures.
- Different boot sessions.
- Different Nick or macOS versions.

Nick may compare partial captures, but it must label the result as partially
complete and identify affected categories.

## Runtime snapshot

Each snapshot uses a versioned schema and contains:

- Snapshot identifier, schema version, timestamp, label, scenario, Nick
  version, macOS version, architecture, device identity token, and boot session
  identifier.
- Capture start/end time and observation duration.
- Running-process records.
- Listening-socket records.
- Observed outbound-connection aggregates.
- Persistence records.
- System and network extension records.
- Sensor, permission, dropped-event, and provider-health records.
- Provider-specific availability and error states.

The local original remains unchanged when an export is sanitized.

## Stable identity and normalization

The schema and normalization rules must be finalized before UI implementation.
Raw operating-system values are evidence; normalized identities are comparison
keys; findings are derived presentation objects. These layers must remain
separate.

Every finding must retain references to the source records that produced it.

### Processes

Stable identity priority:

1. Signing identifier and team identifier.
2. Executable hash where appropriate and affordable.
3. Normalized executable path.
4. Process name only as an explicitly weak fallback.

PID, parent PID, start time, user, executable path, and signing details remain
evidence but PID changes alone do not create a user-facing change.

### Listeners

Listener identity uses:

- Protocol.
- Normalized address scope.
- Listening port.
- Owning executable identity.

Equivalent wildcard representations are normalized carefully while preserving
the underlying IPv4/IPv6 evidence. A PID change after reboot does not create a
new listener when the stable owner is unchanged.

### Connections

Connection identity uses:

- Owning executable identity.
- Protocol.
- Normalized remote destination.
- Remote port or documented service class.

Local ephemeral ports are ignored for primary comparison. Repeated flows are
aggregated with count, first observed, and last observed times. A missing
connection means "not observed during this window," not proof that no
connection occurred.

### Persistence

Persistence identity uses:

- User or system domain.
- Persistence mechanism.
- Label.
- Normalized location.
- Program identity.

Argument changes may be evidence, but secrets in arguments must not be
persisted or exported by default.

### Extensions

Extension identity uses:

- Bundle identifier.
- Team identifier.
- Extension category.
- Containing application identity.

The following states are distinct and must not be collapsed: installed,
enabled, activated, healthy, and recently observed. Categories include Endpoint
Security, content filter, DNS proxy, packet tunnel, and app proxy where
supported data is available.

## Comparison engine

The comparator is a pure deterministic layer with no dependency on live system
APIs. It reports:

- Added records.
- Removed records.
- Materially changed records.
- Visibility unavailable or incomparable.

Ordering, PID changes, local ephemeral ports, and other documented transient
fields must not produce false differences.

Do not label a record malicious merely because it is new.

## Finding model

Every finding has two independent dimensions.

### Evidence classification

- **Observed** — directly supported by captured records.
- **Inferred** — a transparent possible explanation derived from evidence.
- **Incomplete** — missing permission, sensor, time, or comparable evidence
  prevents a reliable conclusion.

### Attention level

- **Important**
- **Review**
- **Informational**

These are diagnostic attention levels, not threat severities.

An Important finding requires a deterministic high-signal condition, such as:

- A security extension was healthy before and unhealthy afterward.
- Network visibility was lost after a configuration change.
- A new listener is exposed on all interfaces and owned by an unsigned
  executable.
- A removed application's system extension remains active and its containing
  application can no longer be found.

Even these findings describe what was observed. They do not claim malware or
causation without proof.

## Results experience

The summary leads with high-signal differences rather than total raw changes.

```text
Intune migration

Before migration → After migration
Completed 12 Aug 2026

3 important changes
8 other observed changes
1 visibility limitation
```

Recommended result groups:

1. Needs attention.
2. Network and extensions.
3. Background and persistence.
4. Processes.
5. Other observed changes.
6. Visibility limitations.

Each finding presents three structurally separate areas:

- **Observed change** — the supported statement.
- **Possible explanation** — cautious heuristic language, when available.
- **Nick cannot confirm** — the missing external context or visibility.

Example:

```text
Observed change

Content filter remained active after its containing app was removed.

Nick observed:
• Before: com.vendor.filter 4.2 — active
• After:  com.vendor.filter 4.2 — active
• Containing app was found before but not after

Possible explanation
This may be a leftover component from the removed security product.

Nick cannot confirm
Whether an MDM profile still manages this extension.

[ View evidence ]
```

Category views show normalized comparison rows with disclosure for raw
evidence. Process views group by stable executable identity rather than PID.
Connection views group by owner and destination rather than individual flows.

## Saved comparison lifecycle

The persisted workflow states are:

- `baselineOnly`
- `capturingFollowUp`
- `ready`
- `partiallyComplete`
- `failed`
- `archived`

Users can rename, continue, export, duplicate as a new comparison, archive,
delete, and inspect capture details. Duplicating creates a new comparison and
never modifies historical evidence.

## Network and MDM diagnostics

There is no separate MDM or Network Diagnostics sidebar tab in 4.1. The chosen
scenario changes result emphasis while using the same collectors and
comparator.

Permitted cautious statements include:

- A content filter is active in the follow-up but absent from the baseline.
- An extension's containing application changed version.
- An installed extension's containing application was not found.
- Network visibility is incomplete because NickNetFilter is not active.
- A DNS proxy or packet tunnel was observed only in the failing snapshot.

Nick must not automatically unload extensions, remove profiles, alter network
settings, renew DHCP, or identify a specific MDM product as the cause without
direct evidence.

## Support bundle and privacy

The result toolbar provides a native Share action that opens a support-bundle
review.

Default contents:

```text
Nick-Runtime-Comparison.zip
├── summary.md
├── comparison.json
├── baseline.sanitized.json
├── follow-up.sanitized.json
└── sensor-health.json
```

Requirements:

- Sanitized export is the default.
- The user sees the exact files and a preview before saving.
- Usernames, device names, home-directory paths, local and remote IP addresses,
  hostnames, domains, and other selected identifiers are redacted or replaced
  with stable per-export pseudonyms.
- Sanitization is deterministic within one bundle so relationships remain
  understandable.
- The local original is never modified by redaction.
- Packet contents, document contents, environment variables, raw browser URLs,
  and command-line secrets are excluded by default.
- Snapshots remain local, use bounded retention, and have visible delete
  controls.
- No upload occurs without a separate explicit future feature and privacy
  review.

## Architecture constraints

Implementation must reuse Nick's current collectors, observation pipeline,
storage, export facilities, and UI conventions where they are suitable. It
must not introduce a parallel security-event pipeline.

Proposed boundaries, subject to repository audit:

- `SnapshotCollector`
- `ProcessSnapshotProvider`
- `NetworkSnapshotProvider`
- `PersistenceSnapshotProvider`
- `SystemExtensionSnapshotProvider`
- `SensorHealthProvider`
- `SnapshotStore`
- `SnapshotComparator`
- `FindingExplainer`
- `RedactionPolicy`
- `ReportExporter`

Rules:

- Providers expose supported data and explicit unavailability.
- The comparator is pure and fixture-driven.
- Explanations cannot upgrade inference into fact.
- Stored schemas are versioned and migrated deliberately.
- Unsupported facts are represented as unavailable rather than guessed.
- Network behavior remains observation-only and fail-open.
- Private APIs are not used.

## Performance budgets

The following are release gates measured on a supported Apple-silicon Mac with
no other Nick scan running. Measurements use a release build and are reported
as the median of three runs unless a maximum is stated.

- An in-progress comparison waiting for its follow-up adds no continuous
  polling and no more than 0.5 percentage points of average CPU over Nick's
  normal idle state.
- Waiting-state memory attributable to Runtime Compare remains below 25 MB.
- A default 30-second capture averages no more than 15% of one CPU core, with
  no sustained interval above 50% of one core for longer than five seconds.
- Capture memory growth remains below 100 MB and returns to within 25 MB of
  its pre-capture level within 30 seconds after completion.
- The transient connection buffer is bounded at 25,000 normalized records.
  Eviction and provider event loss are counted and surfaced as visibility
  limitations; neither is silently discarded.
- A single persisted snapshot is limited to 25 MB. A sanitized support bundle
  is limited to 50 MB. Local retention defaults to 20 comparisons and must be
  user-configurable downward.
- Cancellation is acknowledged immediately, stops new collection work, and
  completes within two seconds except when macOS is finishing an indivisible
  system query. Any longer delay is shown to the user and covered by a timeout.
- The default 30-second capture completes within 45 seconds. The one- and
  five-minute advanced modes complete within their observation duration plus
  15 seconds.
- A burst fixture containing 100,000 raw connection events completes without
  unbounded memory growth, reports all dropped or coalesced events, and keeps
  the UI responsive.

If a budget cannot be met, Nick must reduce collection detail, shorten or
bound work, or defer the affected provider. The release must not normalize a
regression by increasing these limits without updating this roadmap and its
test evidence.

Runtime Compare must not reintroduce continuous expensive polling or make the
Mac feel occupied when no capture is running.

## Acceptance criteria

Nick 4.1 is complete only when:

1. A user can capture two labeled snapshots and compare them without Terminal.
2. Processes, persistence, listeners, connections, extensions, and sensor
   health are represented using a documented versioned schema.
3. Fixtures prove deterministic added, removed, changed, and unavailable
   results.
4. PID, ordering, and ephemeral-port changes do not create false differences.
5. Missing permissions, event loss, different observation windows, and
   inactive sensors produce explicit visibility warnings.
6. Every explanation links to concrete evidence and is labeled Observed,
   Inferred, or Incomplete.
7. A user can preview and export a sanitized Markdown and JSON support bundle.
8. Redaction tests prove that originals are unchanged and exported identifiers
   are consistently pseudonymized.
9. Existing observation, correlation, retention, and buffer-eviction tests
   continue to pass.
10. Integration tests cover realistic processes, listeners, connections,
    persistence, extensions, permissions, reboot/import, cancellation, and
    partial visibility.
11. CPU, memory, dropped events, capture duration, and disk use remain within
    documented release budgets.
12. Signed release artifacts are notarized, stapled, accepted by Gatekeeper,
    and tested with both Nick system extensions active.
13. Documentation states that Nick does not certify compliance, enforce MDM,
    automatically repair networking, or block traffic.

## Implementation gates

No implementation begins until the following design artifacts are reviewed:

1. Repository capability map covering current models, collectors, correlator,
   persistence, exporters, UI, tests, targets, and entitlements.
2. Gap analysis identifying reusable components and conflicts.
3. Final snapshot schema with example records.
4. Stable identity and normalization specification with fixtures for reboot,
   changing PIDs, browser connection bursts, permission loss, upgrades, and
   leftover extensions.
5. Finding and evidence schema.
6. Redaction examples and support-bundle preview specification.
7. Performance budgets and failure-state behavior.

Only after these are stable should implementation proceed in this order:

1. Snapshot provider protocols and sensor health.
2. Pure comparator and fixtures.
3. Versioned storage, migration, import/export, and redaction.
4. Guided Runtime Compare UI and evidence drill-down.
5. Scenario-specific diagnostics and support bundle.
6. Integration with existing exporters where appropriate.
7. Unit, integration, resilience, and performance validation.
8. Signed and notarized clean-Mac runtime validation.
9. Documentation and release-artifact preparation.

Publishing remains a separate approval gate.

## Locked provisional decisions

- Product name: **Nick 4.1 — Runtime Compare and Network Diagnostics**.
- Sidebar destination: **Runtime Compare**.
- Sidebar section: **Diagnostics**.
- Comparison shape: one baseline and one follow-up.
- Default transient-activity observation: 30 seconds.
- Storage: local, versioned, bounded, and user-deletable.
- Export default: sanitized.
- Initial export: Markdown and JSON support bundle.
- Enforcement or remediation: none.
- MDM APIs: none.
- Cross-Mac comparison: unsupported in 4.1.
- Same-Mac reboot/import comparison: supported when identity matches.
- Evidence classifications: Observed, Inferred, and Incomplete.
- Attention levels: Important, Review, and Informational.
- Smart Scan integration: status or navigation only; comparison changes are
  never mixed with malware/security findings.

## Release positioning

Recommended description:

> Nick 4.1 adds local before-and-after runtime snapshots for Mac
> administrators. Compare processes, persistence, listeners, outbound
> connections, and system and network extensions after a hardening or
> management change, with explainable evidence and sanitized support exports.
> Nick observes runtime behavior; it does not replace your MDM, mSCP, EDR, or
> firewall.

This roadmap defines product intent, not current capability. Documentation and
UI must not describe these features as shipped until implementation and all
acceptance gates are complete.
