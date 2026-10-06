# Release verification

Use these checks on the final artifacts. They answer different questions and
are all required; one command does not replace another.

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
