# Security Policy

Nick is a security tool. A vulnerability in Nick is a vulnerability in every Mac that runs it. We take this seriously.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | ✅ |
| Previous minor | ✅ (security fixes only) |
| Older | ❌ |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **Email**: Send a detailed report to **security@3nsofts.com**
2. **GitHub Security Advisories**: [Report via GitHub](https://github.com/EhsanAzish80/Nick/security/advisories/new) (preferred — allows private discussion)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected component (Core engine, privileged helper, YARA integration, etc.)
- Potential impact assessment
- Suggested fix (if you have one)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 7 days
- **Fix timeline**: Critical vulnerabilities patched within 14 days. Others within 30 days.
- **Disclosure**: Coordinated disclosure after the fix is released. You will be credited (unless you prefer anonymity).

### Scope

The following are in scope for security reports:

- **Privileged helper vulnerabilities** — Any way to escalate privileges through the XPC helper
- **Detection engine bypasses** — Methods to evade Nick's monitoring
- **Code signing or notarization issues** — Tampering vectors
- **XPC communication vulnerabilities** — Man-in-the-middle or injection in helper communication
- **YARA engine vulnerabilities** — Crashes or code execution via crafted files
- **Information disclosure** — Nick leaking user data or system information

### Out of Scope

- Social engineering attacks against users
- Denial of service against the Nick process itself
- Issues in third-party operating system components
- Theoretical attacks requiring physical access to an unlocked Mac

## Bug Bounty

We don't currently run a formal bounty program, but we recognize and credit all valid security reports in our release notes and this document. Significant findings may receive a monetary reward at our discretion.

## Security Design Principles

Nick's architecture follows these security principles:

1. **Least privilege**: Each component requests only the permissions it needs
2. **XPC isolation**: The privileged helper is a separate process with a minimal API surface
3. **No network by default**: Nick makes zero network connections unless the user explicitly enables rule update checks
4. **Vendored dependencies**: libyara is vendored and built from source — no dynamic dependency resolution
5. **Hardened runtime**: The app and helper both use hardened runtime with library validation

## Verification

Every official release is:
- Code signed with our Developer ID
- Notarized by Apple
- Published with SHA-256 checksums in the release notes
- Tagged and signed in Git

Verify a release:
```bash
# Check code signature
codesign -dv --verbose=4 /Applications/Nick.app

# Verify notarization
spctl -a -vv /Applications/Nick.app

# Check SHA-256 against published checksum
shasum -a 256 Nick-*.dmg
```
