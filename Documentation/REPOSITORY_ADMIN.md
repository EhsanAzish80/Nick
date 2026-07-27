# Repository Administration

This guide records GitHub settings that cannot be enforced by files in the
repository.

## Required secrets

| Secret | Purpose |
|---|---|
| `CODECOV_TOKEN` | Upload Xcode coverage to Codecov |
| `SONAR_TOKEN` | Run SonarCloud analysis |

Release signing and notarization credentials should be stored in a dedicated
release environment, not general pull-request CI.

## Recommended main-branch rules

Create a ruleset for `main` with:

- pull requests required before merging;
- at least one approving review;
- conversations resolved before merging;
- required status check: `build-and-test`;
- branch required to be current before merging;
- force pushes and branch deletion blocked;
- bypass limited to repository administrators for emergency recovery.

Do not require Codecov patch coverage while it is informational. Make it
blocking only after the baseline is stable and the configured target is
consistently achievable.

## Repository features

- Issues: enabled.
- Discussions: enabled for support and design questions.
- Wiki: disabled; versioned documentation lives in the repository.
- Private vulnerability reporting: enabled.
- Dependabot security updates: enabled.
- Secret scanning and push protection: enabled where available.
- Code scanning: SonarCloud enabled through CI.

## Release discipline

1. Complete [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).
2. Tag the exact verified commit.
3. Publish immutable notarized artifacts and checksums.
4. Update `CHANGELOG.md`, release notes, website download, and Sparkle appcast.
5. Verify the published package on a clean Mac.
