# Nick Enterprise Pilot Roadmap

Status: approved direction; implementation in progress.

Nick Enterprise extends the same Nick runtime engine with managed deployment,
configuration, diagnostics, and evidence export. It does not fork the detector,
replace MDM, certify compliance, or introduce automatic remediation.

## Product promise

> Validate what is actually happening on managed Macs during deployment,
> upgrades, policy changes, and security incidents, then produce bounded,
> privacy-conscious evidence administrators can act on.

## Non-negotiable boundaries

- [x] Use one runtime and detection engine for Community and Enterprise.
- [x] Keep Runtime Compare local, read-only, deterministic, and fail-open.
- [x] Report `matches`, `contradicts`, or `cannot verify`; never claim formal
  compliance without a separately qualified compliance product.
- [x] Do not add remote shell, automatic remediation, traffic interception,
  fleet collection, or an Intune/Jamf/Kandji API dependency in the pilot.
- [x] Do not build a Windows agent during the macOS pilot.
- [ ] Complete legal review before choosing commercial, support, or dual
  licensing terms.

## Phase 0: contracts and acceptance criteria

- [x] Record the product boundary and phased delivery plan.
- [x] Define a versioned managed-configuration contract.
- [x] Define a versioned machine-readable health-report contract.
- [x] Define stable CLI commands, exit codes, and error identifiers.
- [x] Define JSON Schema files for configuration, health, diagnostic export,
  and baseline assertions.
- [x] Write the privacy and threat model, including administrator visibility.
- [x] Set idle CPU, memory, disk-I/O, log-size, and event-loss budgets.
- [ ] Agree on supported macOS versions and Apple silicon/Intel coverage.

## Phase 1: Intune deployment pilot

- [ ] Inventory Nick's Team ID, bundle identifiers, designated requirements,
  system-extension types, network-filter identifiers, and helper services from
  signed release artifacts.
- [ ] Provide a signed and notarized in-place-upgrade PKG.
- [ ] Provide documented Intune Settings Catalog entries for Endpoint Security
  and Network Extension approval.
- [ ] Provide PPPC guidance for Nick and NickExtension using exact designated
  requirements from the signed build.
- [ ] Provide the Network Filter payload and document conflicts with existing
  managed filters, EDRs, VPNs, and content filters.
- [ ] Keep the network provider observation-only and fail-open.
- [ ] Add conflict diagnostics before offering network-filter activation.
- [ ] Validate install-before-policy and policy-before-install ordering.
- [ ] Validate boot-without-user, first login, reboot, upgrade, rollback, and
  uninstall behavior.
- [ ] Ensure setup never loops prompts or requires repeated button presses.

## Phase 2: managed configuration and status

- [x] Read organization-managed settings without allowing local state to
  masquerade as managed policy.
- [x] Support bounded log level, retention, export directory, export format,
  capture duration, sanitization, and optional UI settings.
- [x] Show decoded organization-managed values and their forced-policy
  provenance.
- [ ] Apply each supported managed value to its owning runtime subsystem and
  report the effective value separately from the requested value.
- [x] Add `nickctl status --json` with stable schema and exit codes.
- [ ] Add `nickctl diagnostics --output <path>` with atomic output.
- [ ] Add `nickctl compare` for an administrator-triggered local comparison.
- [x] Report app and schema versions plus evidence-backed Endpoint Security and
  Network Filter enabled, active, responsive, and last-successful-event state.
  Extension version reporting remains pending.
- [x] Treat missing evidence as a visibility limitation, never as proof that a
  component was removed or disabled.

## Phase 3: evidence and support bundles

- [ ] Version all JSON, JSONL, KV, CEF, and Markdown output contracts.
- [ ] Bound and rotate logs; redact usernames, home paths, query strings,
  message contents, and document contents by default.
- [ ] Make exports atomic and include generation time, Nick version, schema
  version, policy provenance, and sensor limitations.
- [ ] Permit MDM collection from an administrator-selected managed directory;
  do not upload directly in the pilot.
- [ ] Add deterministic tests for sanitization, retention, schema migration,
  partial providers, and interrupted writes.

## Phase 4: managed user experience

- [x] Add an **Organization** sidebar destination only when managed
  configuration is detected.
- [x] Show organization-management status, policy provenance, extension health,
  last local status export, limitations, and what administrators can collect.
- [x] Add an evidence-backed Deployment Readiness card with a copyable,
  ticket-friendly support summary.
- [ ] Show the last diagnostic-export result after the diagnostics command is
  implemented.
- [ ] Keep Runtime Compare as a separate diagnostic workflow.
- [ ] Make conflicts and required administrator actions understandable without
  exposing raw Apple framework errors.
- [ ] Add accessibility labels, keyboard navigation, Dynamic Type behavior,
  and useful empty/error states.

## Phase 5: signed-baseline adapter experiment

- [ ] Agree with the baseline publisher on schema ownership, licensing,
  signature format, versioning, and unsupported-rule behavior.
- [ ] Import only signed baseline metadata and runtime-verifiable assertions.
- [ ] Verify publisher identity, signature, checksum, platform, and validity
  window before evaluation.
- [ ] Map assertions to evidence references without interpreting arbitrary code.
- [ ] Return only `matches`, `contradicts`, or `cannot verify`.
- [ ] Embed baseline identity, version, and hash in sanitized support bundles.
- [ ] Keep remediation and fleet enforcement outside Nick.

## Pilot validation matrix

- [ ] Test 5–20 managed Macs in observation-only and network-enabled rings.
- [ ] Cover Automated Device Enrollment and ordinary Device Enrollment.
- [ ] Cover current supported macOS releases and both architectures where
  available.
- [ ] Test coexistence with at least one EDR, VPN, and managed network filter.
- [ ] Verify no ordinary connectivity, AirDrop, Continuity, developer tooling,
  Git, or software-update disruption.
- [ ] Verify deterministic status collection without opening Nick's UI.
- [ ] Verify bounded idle resource use for a full workday.
- [ ] Verify sanitized bundles contain enough evidence for remote diagnosis.
- [ ] Record all manual interventions and reduce them to documented exceptions.

## Pilot intake questions

Before handing a build to an administrator, record:

- Intune enrollment type, assignment rings, macOS versions, architectures, and
  whether users have administrator rights.
- Existing EDR, VPN, DNS proxy, firewall, and network/content filters.
- Required log destination, format, collection cadence, and retention.
- Whether UI is required, optional, or hidden.
- Expected install, update, rollback, and uninstall behavior.
- The exact troubleshooting questions Nick must answer for the administrator.

## Release gates

- [ ] Focused unit, integration, schema, privacy, and migration tests pass.
- [ ] Signed release artifacts pass `codesign`, Gatekeeper, notarization, and
  stapling verification.
- [ ] Clean-Mac and managed-Mac installation tests pass.
- [ ] Upgrade from the last public Nick release preserves approved extensions
  and does not repeat onboarding unnecessarily.
- [ ] Uninstall removes Nick-owned services and files without treating unrelated
  MDM profiles or TCC records as Nick-owned.
- [ ] Pilot administrator signs off on deployment, permissions, health output,
  logs, resource use, and support-bundle usefulness.

## Deferred decision: fleet service

A hosted fleet console is not part of the pilot. It may be considered only
after managed deployment and local evidence collection are proven useful, and
only with a separate privacy, authentication, tenancy, retention, incident
response, and operating-cost design.
