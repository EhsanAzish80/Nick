# Nick installer package

The package installs two applications:

- `/Applications/Nick.app`
- `/Applications/Nick Uninstaller.app`

Nick's Endpoint Security and Network Filter system extensions remain embedded
inside `Nick.app`. The package deliberately does not activate them from an
installer script. Nick's setup walkthrough requests activation, explains each
macOS approval, and verifies that the components are actually running.

## Development package

```sh
./Packaging/build-pkg.sh
```

This creates `build/package/Nick.pkg`. Without an installer identity it is only
appropriate for local testing.

## Signed release package

```sh
INSTALLER_SIGNING_IDENTITY="Developer ID Installer: YOUR NAME (TEAMID)" \
  ./Packaging/build-pkg.sh
```

After building, notarize and staple the package before distribution. The app,
uninstaller, and both nested system extensions must already have valid
Developer ID Application signatures and entitlements before `productbuild`
runs.

The package has no `postinstall` scripts. It only places the two applications
in `/Applications`; all privileged activation stays visible and user-driven in
Nick.

## Complete release

`release.sh` performs the complete production sequence: archive, timestamp-sign
Sparkle's nested helpers, verify the app, sign the installer, notarize, staple,
run Gatekeeper validation, and print the Sparkle enclosure signature.

```sh
./Packaging/release.sh
```

Nick's historical Sparkle key is stored in the login Keychain under the
`nick-legacy` account. Keep that key available so existing installations can
authenticate future updates. Never commit or upload an exported private key.

For v4.0.1, upload `Nick-4.0.1.pkg` to:

`https://3nsofts.com/nick/releases/Nick-4.0.1.pkg`

Then replace the hosted `https://3nsofts.com/nick/appcast.xml` with
`Packaging/Release/v4.0.1/appcast.xml`. The package must not be modified after
its Sparkle signature and length have been recorded in the appcast.

## Website and GitHub disk image

Keep Sparkle pointed directly at the signed package. For manual downloads,
wrap that same notarized package in Nick's branded disk image:

```sh
PKG_PATH=/Users/Shared/Nick-4.0.1-build-408.pkg \
OUTPUT_PATH=/Users/Shared/Nick-4.0.1-build-408.dmg \
./Packaging/build-dmg.sh
```

The DMG is a presentation wrapper around the installer—not a drag-to-Applications
image. It is independently Developer ID signed, notarized, stapled, and checked
by Gatekeeper.

The published checksums are recorded in
`Packaging/Release/v4.0.1/SHA256SUMS.txt`. Recreate that file whenever either
immutable release artifact changes.
