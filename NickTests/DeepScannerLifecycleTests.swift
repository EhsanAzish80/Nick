import XCTest
@testable import Nick

private actor ScanInvocationCounter {
    private(set) var value = 0
    func increment() { value += 1 }
}

@MainActor
final class DeepScannerLifecycleTests: XCTestCase {

    func test_securityEngineOwnsStableDeepScanner() {
        let engine = SecurityEngine()

        XCTAssertTrue(engine.deepScanner === engine.deepScanner)
        XCTAssertTrue(engine.deepScanner.engine === engine)
    }

    func test_resetResultsKeepsScannerReadyForNavigationReuse() {
        let scanner = DeepScanner()

        scanner.resetResults()

        XCTAssertFalse(scanner.isScanning)
        XCTAssertFalse(scanner.isPaused)
        XCTAssertFalse(scanner.isCancelling)
        XCTAssertFalse(scanner.hasCompletedScan)
        XCTAssertTrue(scanner.results.isEmpty)
        XCTAssertTrue(scanner.resultVerdicts.isEmpty)
    }

    func test_verifiedRepositorySourceIsDevelopmentArtifact() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let source = root.appendingPathComponent("Sources/Example.swift")
        try FileManager.default.createDirectory(
            at: root.appendingPathComponent(".git", isDirectory: true),
            withIntermediateDirectories: true
        )
        try FileManager.default.createDirectory(
            at: source.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data().write(to: source)
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }

        let match = YARAMatch(
            ruleName: "macos_launch_constraints_bypass",
            tags: [],
            filePath: source.path,
            metadata: [:]
        )

        XCTAssertEqual(DeepScanner.classify(match: match), .developmentArtifact)
    }

    func test_emailHeuristicInServiceWorkerCacheIsApplicationData() {
        let match = YARAMatch(
            ruleName: "nick_email_html_smuggling",
            tags: ["email", "html_smuggling"],
            filePath: "/Users/test/Library/Application Support/Codex/Default/Partitions/codex-browser-app/Service Worker/CacheStorage/cache/item_0",
            metadata: [:]
        )

        XCTAssertEqual(DeepScanner.classify(match: match), .applicationData)
    }

    func test_officeMacroHeuristicInBundledJavaScriptIsContextMismatch() {
        let match = YARAMatch(
            ruleName: "nick_email_office_macro_dropper",
            tags: ["email", "macro"],
            filePath: "/Applications/Visual Studio Code.app/Contents/Resources/@github/copilot/app.js",
            metadata: ["severity": "HIGH"]
        )

        XCTAssertFalse(DeepScanner.isEmailRuleApplicable(match.ruleName, to: match.filePath))
        XCTAssertEqual(DeepScanner.classify(match: match), .applicationData)
    }

    func test_officeMacroHeuristicRemainsActionableForMacroDocument() {
        let match = YARAMatch(
            ruleName: "nick_email_office_macro_dropper",
            tags: ["email", "macro"],
            filePath: "/Users/test/Downloads/invoice.docm",
            metadata: ["severity": "HIGH"]
        )

        XCTAssertTrue(DeepScanner.isEmailRuleApplicable(match.ruleName, to: match.filePath))
        XCTAssertEqual(DeepScanner.classify(match: match), .suspicious)
    }

    func test_htmlSmugglingHeuristicDoesNotApplyToTestBinary() {
        let match = YARAMatch(
            ruleName: "nick_email_html_smuggling",
            tags: ["email", "html_smuggling"],
            filePath: "/private/tmp/NickTests.xctest/Contents/MacOS/NickTests",
            metadata: ["severity": "HIGH"]
        )

        XCTAssertEqual(DeepScanner.classify(match: match), .applicationData)
    }

    func test_behaviorHeuristicInServiceWorkerCacheIsApplicationData() {
        let match = YARAMatch(
            ruleName: "macos_ptrace_antidebug",
            tags: ["antidebug"],
            filePath: "/Users/test/Library/Application Support/Codex/Default/Partitions/codex-browser-app/Service Worker/CacheStorage/cache/item_1",
            metadata: [:]
        )

        XCTAssertEqual(DeepScanner.classify(match: match), .applicationData)
    }

    func test_behaviorHeuristicInGoogleUpdaterCRXCacheIsApplicationData() {
        let match = YARAMatch(
            ruleName: "macos_ptrace_antidebug",
            tags: ["antidebug"],
            filePath: "/Users/test/Library/Application Support/Google/GoogleUpdater/crx_cache/package",
            metadata: [:]
        )

        XCTAssertEqual(DeepScanner.classify(match: match), .applicationData)
    }

    func test_sourceNamedPathWithoutRepositoryEvidenceRemainsSuspicious() {
        let match = YARAMatch(
            ruleName: "macos_reverse_shell",
            tags: ["backdoor"],
            filePath: "/Users/test/Projects/Tool/Sources/Examples/ReverseShell.swift",
            metadata: ["severity": "HIGH"]
        )

        XCTAssertEqual(DeepScanner.classify(match: match), .suspicious)
    }

    func test_reverseShellOutsideDevelopmentContextRemainsSuspicious() {
        let match = YARAMatch(
            ruleName: "macos_reverse_shell",
            tags: ["backdoor"],
            filePath: "/Users/test/Downloads/update.command",
            metadata: ["severity": "HIGH"]
        )

        XCTAssertEqual(DeepScanner.classify(match: match), .suspicious)
    }

    func test_verifiedHomebrewKegDowngradesOnlyBehavioralRule() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let keg = root.appendingPathComponent("sample/1.0", isDirectory: true)
        let executable = keg.appendingPathComponent("bin/sample")
        try FileManager.default.createDirectory(
            at: executable.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data().write(to: executable)
        try Data("{}".utf8).write(to: keg.appendingPathComponent("INSTALL_RECEIPT.json"))
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }

        XCTAssertTrue(DeepScanner.isVerifiedHomebrewArtifact(
            executable.path,
            cellarRoots: [root.path]
        ))

        let behavioral = YARAMatch(
            ruleName: "macos_keychain_access",
            tags: [],
            filePath: executable.path,
            metadata: ["severity": "medium"]
        )
        let concrete = YARAMatch(
            ruleName: "osx_known_malware_family",
            tags: ["malware"],
            filePath: executable.path,
            metadata: ["severity": "critical"]
        )
        XCTAssertEqual(
            DeepScanner.classify(match: behavioral, cellarRoots: [root.path]),
            .likelySafe
        )
        XCTAssertEqual(
            DeepScanner.classify(match: concrete, cellarRoots: [root.path]),
            .threat
        )
    }

    func test_homebrewLookalikeWithoutReceiptRemainsSuspicious() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let executable = root.appendingPathComponent("sample/1.0/bin/sample")
        try FileManager.default.createDirectory(
            at: executable.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data().write(to: executable)
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }

        XCTAssertFalse(DeepScanner.isVerifiedHomebrewArtifact(
            executable.path,
            cellarRoots: [root.path]
        ))
    }

    func test_launchPropertyListsAreScannedButGenericPropertyListsAreNot() {
        XCTAssertTrue(DeepScanner.shouldScanFile(
            path: "/Library/LaunchAgents/com.example.agent.plist",
            scanRoot: "/Library/LaunchAgents",
            isExecutable: false
        ))
        XCTAssertFalse(DeepScanner.shouldScanFile(
            path: "/Library/Application Support/Example/config.plist",
            scanRoot: "/Library/Application Support",
            isExecutable: false
        ))
        XCTAssertTrue(DeepScanner.shouldScanFile(
            path: "/opt/homebrew/bin/tool",
            scanRoot: "/opt/homebrew/bin",
            isExecutable: true
        ))
    }

    func test_declaredMediumSeverityIsNotPromotedToHigh() {
        let match = YARAMatch(
            ruleName: "macos_network_proxy_intercept",
            tags: [],
            filePath: "/tmp/tool",
            metadata: ["severity": "medium"]
        )

        XCTAssertEqual(DeepScanner.signalSeverity(for: match), .medium)
    }

    func test_criticalTagFallbackIsCaseInsensitive() {
        let match = YARAMatch(
            ruleName: "test_rule",
            tags: ["Critical"],
            filePath: "/tmp/tool",
            metadata: [:]
        )

        XCTAssertEqual(DeepScanner.signalSeverity(for: match), .critical)
    }

    func test_missingSeverityDefaultsToMedium() {
        let match = YARAMatch(
            ruleName: "macos_ptrace_antidebug",
            tags: [],
            filePath: "/tmp/tool",
            metadata: [:]
        )

        XCTAssertEqual(DeepScanner.signalSeverity(for: match), .medium)
    }

    func test_concreteSignatureCannotBeDowngradedByDevelopmentPath() {
        let match = YARAMatch(
            ruleName: "osx_known_malware_family",
            tags: ["malware"],
            filePath: "/Users/test/Projects/SafeTool/Tests/payload",
            metadata: ["severity": "critical"]
        )

        XCTAssertEqual(DeepScanner.classify(match: match), .threat)
        XCTAssertFalse(DeepScanner.canIgnore(match: match))
    }

    func test_onlyNonCriticalBehavioralMatchesCanBeIgnored() {
        let behavioral = YARAMatch(
            ruleName: "macos_ptrace_antidebug",
            tags: [],
            filePath: "/tmp/tool",
            metadata: ["severity": "medium"]
        )
        let criticalBehavioral = YARAMatch(
            ruleName: "macos_ptrace_antidebug",
            tags: [],
            filePath: "/tmp/tool",
            metadata: ["severity": "critical"]
        )

        XCTAssertTrue(DeepScanner.canIgnore(match: behavioral))
        XCTAssertFalse(DeepScanner.canIgnore(match: criticalBehavioral))
    }

    func test_behavioralRulesInRecognizedBuildArtifactsAreDevelopmentContext() {
        let paths = [
            "/Users/test/Library/Developer/Xcode/DerivedData/App/Build/Products/Debug/App",
            "/private/tmp/Nick44Analyze/SourcePackages/artifacts/sparkle/Sparkle.framework.dSYM/Contents/Resources/DWARF/Sparkle",
            "/private/tmp/swiftpm-10417-test-build/checkouts/swift-build/Tests/Fixture.swift",
        ]
        for path in paths {
            let match = YARAMatch(ruleName: "macos_mass_file_rename", tags: [], filePath: path, metadata: ["severity": "high"])
            XCTAssertEqual(DeepScanner.classify(match: match), .developmentArtifact, path)
        }
    }

    func test_genericTemporaryPayloadRemainsSuspicious() {
        let match = YARAMatch(
            ruleName: "macos_reverse_shell", tags: [],
            filePath: "/private/tmp/unknown/payload.command",
            metadata: ["severity": "critical"]
        )
        XCTAssertEqual(DeepScanner.classify(match: match), .suspicious)
    }

    func test_swiftPMArtifactCacheWithWorkspaceStateIsDevelopmentContext() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString + "-packages", isDirectory: true)
        let binary = root.appendingPathComponent(
            "artifacts/vendor/Library.xcframework/ios-arm64/Library.framework/Library"
        )
        try FileManager.default.createDirectory(
            at: binary.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data("{}".utf8).write(to: root.appendingPathComponent("workspace-state.json"))
        try Data().write(to: binary)
        defer { try? FileManager.default.removeItem(at: root) }

        let match = YARAMatch(
            ruleName: "macos_ptrace_antidebug", tags: [], filePath: binary.path,
            metadata: ["severity": "high"]
        )
        XCTAssertTrue(DeepScanner.isVerifiedSwiftPMWorkspaceArtifact(binary.path))
        XCTAssertEqual(DeepScanner.classify(match: match), .developmentArtifact)
    }

    func test_swiftPMScratchProductsWithWorkspaceStateAreDevelopmentContext() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("swiftpm-" + UUID().uuidString, isDirectory: true)
        let binary = root.appendingPathComponent("out/Products/Debug/swift-build")
        try FileManager.default.createDirectory(
            at: binary.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data("{}".utf8).write(to: root.appendingPathComponent("workspace-state.json"))
        try Data().write(to: binary)
        defer { try? FileManager.default.removeItem(at: root) }

        let match = YARAMatch(
            ruleName: "macos_launch_constraints_bypass", tags: [], filePath: binary.path,
            metadata: ["severity": "high"]
        )
        XCTAssertTrue(DeepScanner.isVerifiedSwiftPMWorkspaceArtifact(binary.path))
        XCTAssertEqual(DeepScanner.classify(match: match), .developmentArtifact)
    }

    func test_lookalikeArtifactPathWithoutWorkspaceStateRemainsSuspicious() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        let binary = root.appendingPathComponent("artifacts/vendor/payload")
        try FileManager.default.createDirectory(
            at: binary.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
        try Data().write(to: binary)
        defer { try? FileManager.default.removeItem(at: root) }

        let match = YARAMatch(
            ruleName: "macos_ptrace_antidebug", tags: [], filePath: binary.path,
            metadata: ["severity": "high"]
        )
        XCTAssertFalse(DeepScanner.isVerifiedSwiftPMWorkspaceArtifact(binary.path))
        XCTAssertEqual(DeepScanner.classify(match: match), .suspicious)
    }

    func test_signedShellDoesNotMakeLaunchItemSafe() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("Library/LaunchAgents", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let plist = root.appendingPathComponent("com.example.signed.plist")
        let value: [String: Any] = ["Label": "com.example.signed", "ProgramArguments": ["/bin/sh", "-c", "exit 0"]]
        let data = try PropertyListSerialization.data(fromPropertyList: value, format: .xml, options: 0)
        try data.write(to: plist)
        defer { try? FileManager.default.removeItem(at: root) }
        let match = YARAMatch(ruleName: "macos_launchagent_install", tags: [], filePath: plist.path, metadata: ["severity": "high"])
        XCTAssertEqual(DeepScanner.classify(match: match), .suspicious)
    }

    func test_launchItemWithMissingTargetRemainsSuspicious() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("Library/LaunchAgents", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let plist = root.appendingPathComponent("com.example.missing.plist")
        let value: [String: Any] = ["Label": "com.example.missing", "Program": "/private/tmp/no-such-executable"]
        let data = try PropertyListSerialization.data(fromPropertyList: value, format: .xml, options: 0)
        try data.write(to: plist)
        defer { try? FileManager.default.removeItem(at: root) }
        let match = YARAMatch(ruleName: "macos_launchagent_install", tags: [], filePath: plist.path, metadata: ["severity": "high"])
        XCTAssertEqual(DeepScanner.classify(match: match), .suspicious)
    }

    func test_containerMatchingRejectsLookalikeIdentifier() {
        XCTAssertTrue(DeepScanner.containerIdentifier(
            "group.net.whatsapp.WhatsApp.shared",
            matchesBundleIdentifier: "net.whatsapp.WhatsApp"
        ))
        XCTAssertFalse(DeepScanner.containerIdentifier(
            "group.net.whatsapp.WhatsApp.shared.attacker",
            matchesBundleIdentifier: "net.whatsapp.WhatsApp"
        ))
        XCTAssertFalse(DeepScanner.containerIdentifier(
            "com.apple.Safari.evil",
            matchesBundleIdentifier: "com.apple.Safari"
        ))
    }

    func test_matchKeyIncludesRuleAndCanonicalPath() {
        let first = YARAMatch(ruleName: "rule_a", tags: [], filePath: "/tmp/item", metadata: [:])
        let same = YARAMatch(ruleName: "rule_a", tags: [], filePath: "/private/tmp/item", metadata: [:])
        let otherRule = YARAMatch(ruleName: "rule_b", tags: [], filePath: "/tmp/item", metadata: [:])

        XCTAssertEqual(DeepScanner.matchKey(for: first), DeepScanner.matchKey(for: same))
        XCTAssertNotEqual(DeepScanner.matchKey(for: first), DeepScanner.matchKey(for: otherRule))
    }

    func test_canonicalScanPathsRemoveTmpAliasAndExactDuplicates() {
        let paths = DeepScanner.canonicalUniquePaths([
            "/tmp/example", "/private/tmp/example", "/private/tmp/example",
        ])

        XCTAssertEqual(paths.count, 1)
    }

    func test_duplicateRuleAndCanonicalPathIsReportedOnce() {
        let matches = [
            YARAMatch(ruleName: "rule", tags: [], filePath: "/tmp/example", metadata: [:]),
            YARAMatch(ruleName: "rule", tags: [], filePath: "/private/tmp/example", metadata: [:]),
            YARAMatch(ruleName: "other_rule", tags: [], filePath: "/private/tmp/example", metadata: [:]),
        ]

        XCTAssertEqual(DeepScanner.uniqueMatches(matches).count, 2)
    }

    func test_everyBundledCommunityRuleDeclaresSeverity() throws {
        let testFile = URL(fileURLWithPath: #filePath)
        let projectRoot = testFile.deletingLastPathComponent().deletingLastPathComponent()
        let rulesRoot = projectRoot.appendingPathComponent("Rules/community", isDirectory: true)
        let ruleFiles = try FileManager.default.contentsOfDirectory(
            at: rulesRoot,
            includingPropertiesForKeys: nil
        ).filter { $0.pathExtension == "yar" }
        XCTAssertFalse(ruleFiles.isEmpty)

        let rulePattern = try NSRegularExpression(
            pattern: #"(?ms)^rule\s+([A-Za-z0-9_]+).*?\{(.*?)(?=^rule\s+|\z)"#
        )
        let severityPattern = try NSRegularExpression(
            pattern: #"(?m)^\s*severity\s*=\s*"(?:INFO|LOW|MEDIUM|HIGH|CRITICAL)"\s*$"#
        )
        var checkedRules = 0
        var missing: [String] = []

        for file in ruleFiles {
            let source = try String(contentsOf: file, encoding: .utf8)
            let range = NSRange(source.startIndex..., in: source)
            for match in rulePattern.matches(in: source, range: range) {
                checkedRules += 1
                let name = Range(match.range(at: 1), in: source).map { String(source[$0]) } ?? file.lastPathComponent
                let body = Range(match.range(at: 2), in: source).map { String(source[$0]) } ?? ""
                let bodyRange = NSRange(body.startIndex..., in: body)
                if severityPattern.firstMatch(in: body, range: bodyRange) == nil {
                    missing.append(name)
                }
            }
        }

        XCTAssertGreaterThan(checkedRules, 0)
        XCTAssertTrue(missing.isEmpty, "Rules missing explicit severity: \(missing.joined(separator: ", "))")
    }

    func test_startIsSynchronousAndRejectsOverlappingScan() async {
        let scanner = DeepScanner()
        let counter = ScanInvocationCounter()

        scanner.start(onlyOnPower: false, candidateFiles: ["/tmp/one"]) { _ in
            await counter.increment()
            try await Task.sleep(for: .milliseconds(80))
            return []
        }
        scanner.start(onlyOnPower: false, candidateFiles: ["/tmp/two"]) { _ in
            await counter.increment()
            return []
        }

        XCTAssertTrue(scanner.isScanning)
        await waitUntil { scanner.hasCompletedScan }
        let invocationCount = await counter.value
        XCTAssertEqual(invocationCount, 1)
        XCTAssertEqual(scanner.totalFiles, 1)
    }

    func test_cancelKeepsScannerBusyUntilInFlightWorkReturns() async {
        let scanner = DeepScanner()
        scanner.start(onlyOnPower: false, candidateFiles: ["/tmp/one"]) { _ in
            try await Task.sleep(for: .milliseconds(150))
            return []
        }

        await Task.yield()
        scanner.cancel()
        XCTAssertTrue(scanner.isScanning)
        XCTAssertTrue(scanner.isCancelling)

        await waitUntil { !scanner.isScanning }
        XCTAssertFalse(scanner.isCancelling)
        XCTAssertFalse(scanner.hasCompletedScan)
    }

    func test_scanStoresRuleScopedVerdictAndHonorsBehavioralIgnore() async {
        let scanner = DeepScanner()
        let ignoredPath = "/tmp/ignored"
        let ignoredBehavior = YARAMatch(
            ruleName: "macos_ptrace_antidebug",
            tags: [],
            filePath: ignoredPath,
            metadata: ["severity": "medium"]
        )
        let concrete = YARAMatch(
            ruleName: "osx_known_malware_family",
            tags: ["malware"],
            filePath: ignoredPath,
            metadata: ["severity": "high"]
        )

        scanner.start(
            onlyOnPower: false,
            ignoredPaths: [ignoredPath],
            candidateFiles: [ignoredPath]
        ) { _ in [ignoredBehavior, concrete] }

        await waitUntil { scanner.hasCompletedScan }
        XCTAssertEqual(scanner.resultVerdicts[DeepScanner.matchKey(for: ignoredBehavior)], .suspicious)
        XCTAssertEqual(scanner.resultVerdicts[DeepScanner.matchKey(for: concrete)], .threat)
        XCTAssertEqual(scanner.threatsFound, 1)
    }

    private func waitUntil(
        timeout: Duration = .seconds(2),
        condition: @escaping @MainActor () -> Bool
    ) async {
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: timeout)
        while !condition(), clock.now < deadline {
            try? await Task.sleep(for: .milliseconds(10))
        }
        XCTAssertTrue(condition(), "Timed out waiting for scanner state")
    }
}
