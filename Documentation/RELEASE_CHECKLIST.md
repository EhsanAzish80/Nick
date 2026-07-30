# Release Checklist

## Source and product

- [ ] Marketing version and build number are consistent across all targets.
- [ ] Release notes describe user-visible changes accurately.
- [ ] No active alert classifies Nick's signed app or temporary Xcode build
      artifacts as malware.
- [ ] Medium-confidence heuristic YARA rules cannot deny execution or expose a
      quarantine action.
- [ ] All enabled Smart Scan rows use current health, not persisted assumptions.
- [ ] The full test suite passes with coverage.
- [ ] `git diff --check` passes.

## Signing and packaging

- [ ] Nick, NickExtension, NickNetFilter, NickHelper, Nick Uninstaller, and
      Sparkle helpers have valid Developer ID signatures.
- [ ] Restricted entitlements match the distribution provisioning profiles.
- [ ] Hardened Runtime is enabled for shipping executables.
- [ ] The installer package is signed with Developer ID Installer.
- [ ] Package notarization succeeds and its ticket is stapled.
- [ ] Package Gatekeeper assessment succeeds.
- [ ] The disk image contains the exact notarized package.
- [ ] Disk image signing, notarization, stapling, and Gatekeeper assessment
      succeed.

## Clean-Mac acceptance

- [ ] Install from the published package, not an Xcode build.
- [ ] Setup does not flicker or issue duplicate approval requests.
- [ ] Endpoint Security activates and reports the current build.
- [ ] Full Disk Access guidance covers Nick and NickExtension.
- [ ] Scam Guardian activates after one approval flow.
- [ ] A reserved malicious test domain is reported without interrupting its
      connection.
- [ ] Normal Safari and third-party app networking remains available.
- [ ] Git fetch/push, developer tools, AirDrop, Handoff, and clipboard
      continuity remain available with both extensions enabled.
- [ ] Email Guard detects a safe test fixture and an actionable attachment
      fixture.
- [ ] Quarantine re-validation, move, listing, and restore work.
- [ ] Restart, sleep and wake, and network changes preserve correct state.
- [ ] Idle CPU, memory, and log volume remain acceptable for ten minutes.
- [ ] Update from the previous public build succeeds through Sparkle.
- [ ] Uninstall restores normal networking and removes both applications,
      system extensions, configuration, and generated files.

## Publication

- [ ] Upload the exact package named by the appcast enclosure.
- [ ] Confirm its hosted byte length and SHA-256 match the local artifact.
- [ ] Upload the appcast only after the package URL is reachable.
- [ ] Upload the disk image for website and GitHub manual downloads.
- [ ] Confirm release notes, download links, and minimum macOS version.
- [ ] Install the public artifact once more before announcing the release.
