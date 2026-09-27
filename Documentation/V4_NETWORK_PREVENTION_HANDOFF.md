# Nick 4.0 Network Prevention Status

Updated: 2026-07-27

This file is retained as the engineering handoff for Scam Guardian. The broader
roadmap is in `Documentation/ROADMAP.md`, and release acceptance is in
`Documentation/RELEASE_CHECKLIST.md`.

## Implemented

- `NickNetFilter.systemextension` is embedded in Nick.
- The parent app requests system-extension activation and configures
  `NEFilterManager`.
- The provider filters socket flows and fails open when its configuration is
  missing or invalid.
- Domain and app allowlists run before block policy.
- Scam Guardian normalizes exact domains, subdomains, IDNs, IP literals, and
  registrable domains using the bundled Public Suffix List.
- Block events are bounded and omit URLs, query strings, paths, and payloads.
- Settings includes enable, disable, emergency-disable, and allowlist controls.
- Setup and Smart Scan use current extension and filter state.
- Signed network-rule envelopes support version, issue time, expiry, and
  Ed25519 verification.
- Deterministic policy and lifecycle tests are included in the Nick scheme.

## Release state

Nick 4.0 build 404 has a Developer ID signed, notarized, stapled, and
Gatekeeper-accepted package and disk image. Packaging success is not runtime
proof. Each published artifact must still pass the clean-Mac matrix.

The embedded rule-feed public key is a development placeholder. Do not publish
downloaded rule bundles until the production public key is embedded and the
matching private key is stored outside the application and repository.

## Required live validation

1. Restart before testing if older extensions are waiting for uninstall.
2. Install only the current notarized package.
3. Confirm Nick, NickExtension, and NickNetFilter report version 4.0 build 404.
4. Confirm fresh Endpoint Security and Network Filter health.
5. Confirm a normal domain is allowed.
6. Confirm the reserved Scam Guardian test destination is blocked.
7. Confirm the block event appears with its reason and allowlist action.
8. Test Safari, third-party browsers, VPN coexistence, sleep and wake, and
   network transitions.
9. Disable Network Protection and verify normal networking immediately.
10. Uninstall while protection is enabled and verify no active Nick filter or
    system extension remains.

## Safety invariants

- Fail open on missing, unreadable, or malformed configuration.
- Never block solely because a connection uses an unusual port.
- App allowlist wins first, domain allowlist second, blocking policy last.
- Explanations never determine enforcement.
- Do not store browsing history or page content.
- Keep an emergency disable path available.
- Do not add a packet tunnel or DNS proxy without a demonstrated requirement
  the content filter cannot meet.

## Future signed-rule feed

Before enabling automatic rule updates:

1. Generate the production Ed25519 key pair offline.
2. Embed only the public key.
3. Sign a versioned, expiring rule envelope in release infrastructure.
4. Add last-known-good retention and rollback protection.
5. Test invalid signature, malformed payload, expiry, downgrade, unavailable
   network, and interrupted update cases.
6. Publish rule source, version, signing state, and last successful update in
   Nick.
