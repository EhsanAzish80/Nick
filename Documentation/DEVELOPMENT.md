# Development and CI

## Supported toolchain

- macOS 26 or later.
- Xcode 26 or later.
- Swift 6.
- The checked-in `Nick.xcodeproj` is authoritative.

`project.yml` is retained as project-generation documentation but does not
fully represent the filesystem-synchronized groups and release signing state.
Do not regenerate the project for ordinary source-file changes.

## Local build

```sh
xcodebuild build \
  -project Nick.xcodeproj \
  -scheme Nick \
  -destination "platform=macOS" \
  CODE_SIGN_IDENTITY="" \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=NO
```

This validates compilation without requiring the maintainer's restricted
entitlements. It does not validate system-extension activation.

## Tests and coverage

```sh
rm -rf TestResults.xcresult

xcodebuild test \
  -project Nick.xcodeproj \
  -scheme Nick \
  -destination "platform=macOS" \
  -enableCodeCoverage YES \
  -resultBundlePath TestResults.xcresult \
  CODE_SIGN_IDENTITY="" \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=NO
```

Inspect the summary:

```sh
xcrun xcresulttool get test-results summary --path TestResults.xcresult
```

Generate SonarCloud generic coverage:

```sh
./Scripts/xccov-to-sonarqube.sh TestResults.xcresult > sonar-coverage.xml
```

The Codecov conversion excludes `NickTests` and `NickIntegrationTests`.
Coverage must describe production code exercised by tests, not the test source
files executing themselves. The checked-in Codecov project target is an honest
baseline and should be raised as production coverage improves.

## CI quality gates

The GitHub workflow:

1. Checks out full history and Git LFS objects.
2. Selects the newest installed Xcode.
3. Builds Nick, NickExtension, NickNetFilter, NickHelper, and NickUninstaller
   through the Nick scheme.
4. Runs unit and integration tests with Xcode coverage enabled.
5. Uploads the result bundle as a diagnostic artifact.
6. Uploads coverage to Codecov.
7. Converts coverage and runs SonarCloud analysis when `SONAR_TOKEN` exists.

Configure these repository secrets:

- `CODECOV_TOKEN`
- `SONAR_TOKEN`

In SonarCloud, disable Automatic Analysis. The repository uses CI-based
analysis so test coverage is attached to the same commit and pull request.

## Static-analysis scope

`sonar-project.properties` includes application, extension, helper, shared, and
packaging source. Tests are classified separately. Vendored YARA headers and
static libraries, generated build products, packages, disk images, Xcode result
bundles, and Xcode user state are excluded.

## Before requesting review

```sh
git diff --check
git status --short
```

Then run the full test command above. Document any test that is skipped because
the runner lacks a macOS service. A successful unsigned build is not a
substitute for the clean-Mac system-extension matrix.

## Signed runtime validation

For a release candidate:

1. Restart to clear system extensions waiting for uninstall.
2. Install only the current notarized package.
3. Confirm the installed app and both system extensions have the intended
   version and build.
4. Confirm fresh Endpoint Security and Network Filter health files.
5. Verify a normal website is allowed and the reserved Scam Guardian test
   destination is blocked.
6. Test an Email Guard fixture, quarantine, restore, update, and uninstall.
7. Observe idle CPU, memory, and logs for at least ten minutes.
