# External Security Review Scope for Nick 5.0

This package defines the independent review boundary. It identifies privileged
surfaces and required evidence without publishing known exploit details,
credentials, production keys, private incident data, or unresolved findings.
Findings must be reported through the private process in `SECURITY.md`.

## Review objective

Determine whether an untrusted local process, malicious file, compromised user
process or crafted event can misuse Nick's privileges, hide protected evidence,
cross a trust boundary, or cause unsafe remediation. Confirm that optional
local learning cannot affect protected detections or privileged actions.

## In-scope trust boundaries

1. **App ↔ Endpoint Security extension XPC**
   - Listener-side exact code-signing requirement and audit-token identity.
   - Per-action Authorization Services rights and lifetime of authorization
     forms/references.
   - Root-owned settings, incident/evidence, FIM and health data.
   - Mixed-version request behavior and replay/substitution resistance.
2. **Endpoint Security authorization and notification paths**
   - Deadline handling, fail-open/fail-closed decisions, path canonicalization,
     rename destinations, read-only-volume mutes and queue overload behavior.
   - Signing identity validation from audit tokens, Team ID/signing identifier,
     cdhash caching, interpreter exclusions and fake-identity resistance.
3. **Quarantine and restore**
   - Scan-to-move identity, descriptor-based operations, symlink/path races,
     ownership and mode restoration, old-record compatibility and rollback.
4. **Tamper protection and uninstall**
   - Nick/Sparkle/Apple-installer maintenance identities, real Trash locations,
     protected write/create/remove/rename operations and documented uninstall.
5. **Evidence and verdict lifecycle**
   - Protected-tier invariants, deduplication/coalescing, suppression boundaries,
     retention/eviction, tombstones, authenticated verdict actors and atomic
     persistence.
6. **Network extension and update supply chain**
   - Observation-only boundary, signed-rule validation, downgrade behavior,
     Sparkle EdDSA verification, installer identity, notarization and appcast
     parsing/transport.
7. **Local explanation and verdict learning**
   - Untrusted-string delimiting, output isolation from decisions, validated
     actor identity, root-controlled enablement, two-incident activation,
     expiration/caps and review-tier-only influence.

## Primary code map

Reviewers receive the exact candidate commit and should trace, at minimum:

- `NickExtension/` — Endpoint Security client, XPC listener/service, protected
  storage, quarantine, FIM, tamper and scanner paths.
- `NickNetFilter/` — Network Extension provider, rule validation and events.
- `Nick/Core/Security/`, `Nick/Core/Correlation/`, `Nick/Core/Models/` — identity,
  evidence tiers, correlator and incident lifecycle.
- `Nick/Core/YARAEngine/` and `Rules/` — parser/engine boundary and confidence
  metadata; use safe fixtures only.
- `Nick/App/`, settings and extension-management code — authorization requests,
  health presentation, verdict actions and mixed-version errors.
- `Packaging/`, `.github/workflows/` and dependency manifests — build, signing,
  notarization, appcast and supply-chain controls.

The final handoff must list the exact files and commit actually reviewed. If a
path moved, reviewers should follow repository references rather than assume a
similar name is equivalent.

## Required adversarial cases

- Same-team wrong identifier and self-signed fake-Team-ID XPC callers.
- Never-authorized, expired, replayed and wrong-right authorization forms.
- File replacement between detection, verdict, quarantine and restore.
- Symlinks and rename/copy/link destinations crossing protected boundaries.
- UserDefaults/settings-file tampering and mixed app/extension versions.
- Event bursts, deadline pressure and retention flooding around a red incident.
- Malformed YARA, network-rule, appcast, incident and explanation inputs.
- Crafted actor names, paths and prompt-like strings that try to influence an
  explanation or learned decision.

No test may use live malware, real credentials or irreversible changes. Run
destructive fixtures only in an isolated test environment with a documented
rollback.

## Evidence supplied

- Architecture and data-flow documents matched to the candidate commit.
- Entitlements, Info.plists, signing requirements and authorization-right
  definitions for every shipping target.
- Focused unit/adversarial results, full CI, ~17k files (cap 120k) benign-corpus
  report, physical-Mac checklist, latency/event-loss/resource measurements,
  SBOM and dependency/provenance manifests.
- Signed/notarized candidate checksums and expected verification output.
- Private known-issues and earlier review notes shared through an agreed secure
  channel, not committed to the public repository.

## Deliverable and severity handling

The reviewer provides a private report with reproduction conditions, affected
boundary, impact, severity rationale and remediation guidance. Critical/high
findings block 5.0. Medium findings are fixed or explicitly accepted by Ehsan
with compensating controls and a target release. Public disclosure happens only
after affected users have an update and a coordinated disclosure date exists.
