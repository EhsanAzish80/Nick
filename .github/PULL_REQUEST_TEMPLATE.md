## Summary

Explain the problem, the approach, and the user-visible result.

Closes #

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Detection improvement (new/updated YARA rule or correlation rule)
- [ ] False positive fix
- [ ] Documentation
- [ ] Performance improvement
- [ ] Build, packaging, or release engineering

## Risk and security impact

Describe changes to entitlements, permissions, XPC, persistence, networking,
privacy, update delivery, or privileged behavior. Write "None" when not
applicable.

## Testing

- [ ] Relevant automated tests were added or updated
- [ ] The complete test suite passes using
      [the documented command](../Documentation/DEVELOPMENT.md)
- [ ] `git diff --check` passes
- [ ] Tested on macOS 26+

## False positive check (for detection changes)

- [ ] Tested against a clean macOS install
- [ ] Tested against a developer Mac (Xcode, Homebrew, etc.)
- [ ] No new false positives observed

## System-extension and release checks

- [ ] Not applicable
- [ ] Endpoint Security health was verified on an installed signed build
- [ ] Network filter health and a real blocked-domain event were verified
- [ ] Clean-install, update, and uninstall behavior were verified

## Screenshots or logs

Add screenshots for UI changes and sanitized logs for operational changes.

## Checklist

- [ ] Code follows the project's Swift 6 strict concurrency requirements
- [ ] New dependencies are justified and security-reviewed
- [ ] User-facing behavior and the changelog are updated when appropriate
- [ ] `Documentation/SECURITY_AUDIT.md` is updated for trust-boundary changes
- [ ] No secrets, signing assets, personal paths, or live malware are included
- [ ] The pull request is focused and its title is descriptive
