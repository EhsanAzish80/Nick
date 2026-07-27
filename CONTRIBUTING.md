# Contributing to Nick

Thanks for helping make macOS security more understandable and effective.
Before opening a public issue, review [SUPPORT.md](SUPPORT.md). Report
vulnerabilities privately through the process in [SECURITY.md](SECURITY.md).

## Ways to contribute

### Bug reports and false positives

Use the matching
[issue form](https://github.com/EhsanAzish80/Nick/issues/new/choose). Include:

- macOS version and Mac model
- Nick version
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs with secrets and personal paths removed
- For false positives, the process or file that was flagged and why you believe
  it is safe

### YARA rules

Submit new detection rules for macOS-specific threats:

1. Place community rules under `Rules/community/`.
2. Follow the naming convention `threat_family_variant.yar`, for example
   `atomic_stealer_v2.yar`.
3. Include metadata in every rule:

   ```yara
   rule atomic_stealer_v2 {
       meta:
           author = "Your Name"
           description = "Detects Atomic Stealer v2 macOS credential theft malware"
           reference = "https://link-to-analysis"
           date = "2026-05-21"
           severity = "high"
           hash = "sha256_of_sample_if_available"
       strings:
           // your strings
       condition:
           // your condition
   }
   ```
4. Test the rule against representative clean files to minimize false
   positives.
5. Open a pull request with references, safe test fixtures, and a brief
   explanation of the detection.

### Behavioral scoring model

The CoreML threat scoring model can be improved with:

- New training data (anonymized behavioral patterns from confirmed threats)
- Feature engineering suggestions (new signals to correlate)
- Model architecture improvements
- False positive / false negative analysis

See `Models/Training/` for the training pipeline and data format.

### Code contributions

1. Fork the repository
2. Create a focused branch, such as `fix/alert-copy` or
   `feature/network-health`
3. Make your changes
4. Run the full build and coverage command in
   [Documentation/DEVELOPMENT.md](Documentation/DEVELOPMENT.md)
5. Commit with a concise imperative message
6. Push the branch and open a pull request

### Documentation

- Fix typos, clarify explanations, add examples
- Document detection logic for specific threat types
- Write guides for common use cases

## Code standards

### Swift

- Swift 6.0 with strict concurrency checking
- Follow Apple's API Design Guidelines
- Use `async/await` for asynchronous operations
- Prefer value types (structs, enums) over reference types where appropriate
- All public APIs must have documentation comments

### Architecture rules

- `Nick/Core/` must have no UI dependencies; it is the testable detection engine.
- `Nick/App/` depends on `Nick/Core/`, never the reverse.
- Privileged and extension XPC protocols must expose the smallest justified API.
- The main app must authenticate extension health before reporting protection.
- Network enforcement must fail open when configuration is unavailable.
- New dependencies require a clear justification and security review. Sparkle
  is the currently approved managed Swift package.
- Vendored libyara updates must record the exact upstream version and pass the
  complete false-positive test suite.

### Testing

- Every detection capability must have corresponding unit tests
- Include positive tests and negative false-positive tests
- Use realistic but safe fixtures; never commit live malware
- A system-extension build is not deployment proof. Release claims require the
  clean-Mac checks in
  [Documentation/RELEASE_CHECKLIST.md](Documentation/RELEASE_CHECKLIST.md).

## Pull request process

1. Keep each pull request focused on one concern.
2. Explain why the change is needed and link a relevant issue.
3. Include tests for new or changed detection behavior.
4. Update documentation for user-visible or operational changes.
5. Complete the pull request checklist and respond to review feedback.

## Security vulnerabilities

Follow the [responsible disclosure process](SECURITY.md) before submitting a
security fix. Do not disclose an uncoordinated vulnerability in a public issue
or pull request.

## Code of conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing to Nick, you agree that your contributions will be licensed
under the [AGPL-3.0 License](LICENSE).
