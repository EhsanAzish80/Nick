# Contributing to Nick

Thanks for your interest in making Mac security better. Nick is built by the community, for the community.

## Ways to Contribute

### 🐛 Bug Reports & False Positives
Found a bug or a false positive detection? Open an [issue](https://github.com/EhsanAzish80/Nick/issues/new) with:
- macOS version and Mac model
- Nick version
- Steps to reproduce
- Expected vs actual behavior
- For false positives: the process/file that was flagged and why you believe it's safe

### 🧬 YARA Rules
Submit new detection rules for macOS-specific threats:

1. Place your rule in the appropriate directory under `Rules/` (stealers, backdoors, adware, ransomware, or community)
2. Follow the naming convention: `threat_family_variant.yar` (e.g., `atomic_stealer_v2.yar`)
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
4. Test your rule against known-good files to minimize false positives
5. Open a PR with the rule and a brief description of the threat it detects

### 🧠 Behavioral Scoring Model
The CoreML threat scoring model can be improved with:
- New training data (anonymized behavioral patterns from confirmed threats)
- Feature engineering suggestions (new signals to correlate)
- Model architecture improvements
- False positive / false negative analysis

See `Models/Training/` for the training pipeline and data format.

### 💻 Code Contributions
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests: `xcodebuild test -scheme NickTests`
5. Commit with a clear message: `git commit -m "Add SSH tunnel detection to NetworkAnalyzer"`
6. Push and open a PR

### 📖 Documentation
- Fix typos, clarify explanations, add examples
- Document detection logic for specific threat types
- Write guides for common use cases

## Code Standards

### Swift
- Swift 6.0 with strict concurrency checking
- Follow Apple's API Design Guidelines
- Use `async/await` for asynchronous operations
- Prefer value types (structs, enums) over reference types where appropriate
- All public APIs must have documentation comments

### Architecture Rules
- `Core/` must have **zero** UI dependencies — it's a pure detection engine
- `App/` depends on `Core/` but never the reverse
- `Helper/` has the smallest possible API surface — every XPC method must be justified
- No third-party Swift packages. Apple frameworks and POSIX APIs only.
- `libyara` is the sole C dependency and must remain vendored

### Testing
- Every detection capability must have corresponding unit tests
- Include both positive tests (does it catch the threat?) and negative tests (does it avoid false positives?)
- Integration tests should use realistic but safe mock data — never include actual malware in the repo

## Pull Request Process

1. **One PR = one concern.** Don't mix a bug fix with a new feature.
2. **Describe the why**, not just the what. Link to the issue if one exists.
3. **Include tests** for any new detection logic.
4. **Update docs** if your change affects user-facing behavior.
5. A maintainer will review within 7 days. We may request changes — this is collaborative, not adversarial.

## Security Vulnerabilities

If your contribution involves a security fix, please follow the [responsible disclosure process](SECURITY.md) first. Do not submit security fixes as public PRs without prior coordination.

## Code of Conduct

Be respectful. Be constructive. We're all here to make Macs safer. Toxic behavior, harassment, or bad-faith contributions will result in a ban.

## License

By contributing to Nick, you agree that your contributions will be licensed under the [AGPL-3.0 License](LICENSE).
