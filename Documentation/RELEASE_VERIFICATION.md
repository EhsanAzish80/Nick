# Release verification

Use these checks on the final artifacts. They answer different questions and
are all required; one command does not replace another.

All maintained release scripts use the `NickNotary` keychain profile by
default. Create that profile locally with `notarytool store-credentials`; never
commit Apple credentials or pass an app-specific password on a command line.
Override `NOTARY_PROFILE` only for an intentionally separate local keychain
profile.

```sh
pkgutil --check-signature Nick.pkg
xcrun stapler validate Nick.pkg
spctl -a -vv -t install Nick.pkg
codesign --verify --deep --strict --verbose=2 Nick.app
```

Expected results:

- `pkgutil` reports a Developer ID Installer certificate chain. It verifies
  the package signature, but does not establish notarization or Gatekeeper
  acceptance.
- `stapler validate` reports that the ticket is valid.
- `spctl` reports `accepted` and `source=Notarized Developer ID`.
- `codesign` exits successfully and reports that the application satisfies its
  designated requirement.

After uploading the package and appcast, run:

```sh
Packaging/validate-live-appcast.sh https://3nsofts.com/nick/appcast.xml BUILD
```

Expected output reports the live build, its lower predecessor, and the exact
hosted package length. The validator also requires valid XML, an EdDSA
signature, and a matching package download. Before publishing a new appcast,
also confirm every package enclosure declares
`sparkle:installationType="package"`.

## Update reminder test

Shipped 4.x builds use the production feed embedded in their Info.plist. On a
Mac with build 428 installed, use **Check for Updates** and confirm that the
live feed offers build 430.

Test the new reminder UI only with a Debug build and an HTTPS staging feed:

```sh
xcodebuild -project Nick.xcodeproj -scheme Nick -configuration Debug \
  NICK_DEBUG_UPDATE_FEED_URL=https://staging.example/nick/appcast.xml build
```

Use a staging item whose build number is higher than the Debug app's build.
Release builds leave this override empty and continue to use the production
`SUFeedURL`. Do not put a staging URL into the Release configuration or the
live appcast.
