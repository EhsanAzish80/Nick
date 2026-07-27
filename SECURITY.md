# Security Policy

Nick operates on security-sensitive macOS data and includes privileged and
system-extension components. Please report suspected vulnerabilities privately.
Do not open a public issue for a vulnerability, exploit, credential, signing
material, or malware sample.

## Supported versions

| Version | Security updates |
|---|---|
| 4.x development builds | Supported |
| 3.x latest published release | Supported |
| 2.x and earlier | Not supported |

Only artifacts published through the
[official GitHub Releases page](https://github.com/EhsanAzish80/Nick/releases)
or the Nick update feed are supported. Source builds and modified packages are
outside the release support boundary.

## Reporting a vulnerability

Use one of these private channels:

1. [Open a private GitHub security advisory](https://github.com/EhsanAzish80/Nick/security/advisories/new)
2. Email [security@3nsofts.com](mailto:security@3nsofts.com)

Include, when possible:

- the affected Nick and macOS versions;
- the affected component and expected security boundary;
- reproduction steps or a minimal proof of concept;
- impact and prerequisites;
- relevant logs with personal data and secrets removed.

Do not attach live malware to an issue or email. Coordinate sample transfer
privately after acknowledgment.

## Response targets

- Initial acknowledgment: within 2 business days.
- Initial severity assessment: within 7 calendar days.
- Status updates for confirmed high-severity issues: at least every 14 days.

These are response targets, not guaranteed remediation deadlines. Resolution
time depends on complexity, Apple platform behavior, and whether entitlement or
operating-system changes are required.

## Disclosure

Please allow reasonable time for investigation and release preparation before
public disclosure. Nick will credit reporters who request attribution and will
coordinate disclosure timing for confirmed vulnerabilities.

## Security design and audit evidence

- [Architecture and trust boundaries](ARCHITECTURE.md)
- [Detailed security audit record](Documentation/SECURITY_AUDIT.md)
- [Release verification checklist](Documentation/RELEASE_CHECKLIST.md)

The audit record documents historical findings and remediations. It is not a
certification, warranty, or claim that Nick detects every threat.
