# Nick Enterprise Privacy and Threat Model

## Purpose

Nick Enterprise collects bounded runtime evidence on a managed Mac so an
administrator can diagnose deployment, extension, persistence, listener, and
connection changes. The pilot does not create a fleet service or upload data.

## Trust boundaries

1. **Containing app** presents status and user-visible diagnostics.
2. **Endpoint Security extension** observes authorized file and process events.
3. **Network Filter extension** observes connection destinations and remains
   fail-open; it does not inspect page content or TLS payloads.
4. **Privileged helper** performs only its documented, authenticated local
   operations.
5. **Managed preferences** are accepted only from the organization-managed
   preferences source, not ordinary local defaults.
6. **Export directory** is chosen by managed configuration or an explicit
   administrator action. The pilot performs no remote upload.
7. **Baseline publisher** is outside Nick's trust boundary until its signature,
   key identity, checksum, platform, and validity window are verified.

## Data collected

- Nick, macOS, architecture, and schema versions.
- Component installed, enabled, responsive, and last-evidence state when those
  facts are observable.
- Bounded processes, persistence entries, listeners, connection destinations,
  system extensions, and provider limitations used by Runtime Compare.
- Stable error identifiers and operational timings.

## Data excluded from enterprise exports

- Packet bodies, TLS contents, browser history, email bodies, message content,
  document content, passwords, tokens, cookies, and private keys.
- Raw usernames, home-directory prefixes, local IP addresses, and query strings
  when a sanitized export is generated.
- Arbitrary files requested by a baseline or remote administrator.

## Administrative transparency

When managed configuration is detected, Nick must show:

- The organization name when supplied.
- Which settings are managed and their effective values.
- What categories may appear in a diagnostic bundle.
- The destination and last generation time of local exports.
- Visibility limitations and provider failures.

Nick must not label ordinary local preferences as organization policy.

## Threats and controls

| Threat | Required control |
| --- | --- |
| Malicious local preference masquerades as MDM policy | Read managed configuration from a distinct managed source |
| Baseline supplies executable or path-traversal content | Metadata-only assertions; no execution; reject absolute and traversal paths |
| Tampered baseline | Verify signature, key identity, SHA-256, platform, and validity window before evaluation |
| Diagnostic bundle leaks private data | Mandatory sanitization in pilot, exact preview where UI exists, deterministic redaction tests |
| Export is partially written | Write to a temporary sibling and atomically rename only after hashes and manifest succeed |
| Logs exhaust disk | Enforce byte and age limits with rotation |
| Missing provider evidence becomes a false incident | Represent it as `cannotVerify` and include a limitation |
| Another network filter causes connectivity failure | Diagnose coexistence before activation; observation-only and fail-open behavior |
| Administrator silently weakens protection | Managed values cannot disable sanitization or change fail-open safety boundaries |
| Fleet service expands surveillance surface | No fleet service or direct upload in the pilot |

## Retention and deletion

- Managed retention accepts 1–90 days; default is 14 days.
- Deleting an export removes only Nick-owned artifacts from the configured
  directory.
- Uninstall must not remove unrelated MDM profiles, other vendors' filters, or
  system privacy records it cannot prove are exclusively Nick-owned.

## Security review gates

- Validate every schema and malformed-input path.
- Fuzz or property-test baseline metadata and export paths before pilot use.
- Review designated requirements and XPC caller validation from signed builds.
- Re-run coexistence tests with every supported EDR/VPN/filter combination.
- Conduct a separate design review before introducing authentication, upload,
  tenancy, or a hosted service.
