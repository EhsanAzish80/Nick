import XCTest
@testable import Nick

final class ResponsibleAppAttributionTests: XCTestCase {
    private struct Resolver: ResponsibleProcessIdentityResolving {
        let identities: [Int32: ResponsibleAppIdentity]

        func identity(pid: Int32, pathHint: String?) -> ResponsibleAppIdentity? {
            identities[pid]
        }
    }

    func test_codexCLILikeChainAttributesChatGPTWithShortViaChain() {
        let tree = ProcessTree()
        tree.recordExec(
            pid: 999, ppid: 1,
            path: "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT", args: []
        )
        tree.recordExec(
            pid: 1_060, ppid: 999,
            path: "/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI", args: []
        )
        tree.recordExec(pid: 1_842, ppid: 1_060, path: "/bin/zsh", args: ["zsh", "-c"])

        let result = tree.responsibleApp(
            actorPID: 1_842,
            // ES may nominate the embedded CLI. It remains a "via" hop,
            // while ancestry supplies the user-visible application.
            responsiblePID: 1_060,
            resolver: Resolver(identities: [999: chatGPTIdentity, 1_060: chatGPTIdentity])
        )

        XCTAssertEqual(result.displayLine, "ChatGPT ran this · via Codex CLI → zsh")
        XCTAssertEqual(result.chain, ["ChatGPT", "Codex CLI", "zsh"])
        XCTAssertLessThanOrEqual(result.chain.count, 5)
    }

    func test_responsibleHelperWithLaunchdParentAttributesAppAndKeepsHelperAsVia() {
        let tree = ProcessTree()
        tree.recordExec(
            pid: 2_001, ppid: 1,
            path: "/Applications/ChatGPT.app/Contents/Helpers/ChatGPTHelper", args: []
        )

        let result = tree.responsibleApp(
            actorPID: 2_001,
            responsiblePID: 2_001,
            resolver: Resolver(identities: [2_001: chatGPTIdentity])
        )

        XCTAssertEqual(result.displayLine, "ChatGPT ran this · via ChatGPTHelper")
        XCTAssertEqual(result.chain, ["ChatGPT", "ChatGPTHelper"])
    }

    func test_terminalLaunchedShellAttributesTerminalWithoutNoisyShellSuffix() {
        let tree = ProcessTree()
        tree.recordExec(
            pid: 500, ppid: 1,
            path: "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", args: []
        )
        tree.recordExec(pid: 501, ppid: 500, path: "/bin/zsh", args: ["zsh"])
        let terminal = ResponsibleAppIdentity(
            name: "Terminal", bundleID: "com.apple.Terminal", teamID: "APPLE_PLATFORM",
            signing: .applePlatform,
            path: "/System/Applications/Utilities/Terminal.app"
        )

        let result = tree.responsibleApp(
            actorPID: 501, responsiblePID: 500,
            resolver: Resolver(identities: [500: terminal])
        )

        XCTAssertEqual(result.displayLine, "Terminal ran this")
    }

    func test_fileBehaviorFromCodexChainAttributesChatGPTViaCodexCLIAndCMake() {
        let tree = ProcessTree()
        tree.recordExec(
            pid: 999, ppid: 1,
            path: "/Applications/ChatGPT.app/Contents/MacOS/ChatGPT", args: []
        )
        tree.recordExec(
            pid: 1_060, ppid: 999,
            path: "/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI", args: []
        )
        tree.recordExec(pid: 1_842, ppid: 1_060, path: "/opt/homebrew/bin/cmake", args: [])

        let result = tree.responsibleApp(
            actorPID: 1_842,
            responsiblePID: 999,
            resolver: Resolver(identities: [999: chatGPTIdentity])
        )

        XCTAssertEqual(result.displayLine, "ChatGPT ran this · via Codex CLI → cmake")
    }

    func test_brokenChainDoesNotGuessAnApplication() {
        let tree = ProcessTree()
        tree.recordExec(pid: 700, ppid: 699, path: "/bin/zsh", args: [])

        let result = tree.responsibleApp(
            actorPID: 700, responsiblePID: 699,
            resolver: Resolver(identities: [:])
        )

        XCTAssertEqual(result.displayName, "Unknown app")
        XCTAssertEqual(result.displayLine, "Unknown app ran this")
    }

    func test_unsignedResponsibleApplicationIsReportedAsUnsigned() {
        let tree = ProcessTree()
        tree.recordExec(
            pid: 800, ppid: 1,
            path: "/Applications/Unsigned.app/Contents/MacOS/Unsigned", args: []
        )
        tree.recordExec(pid: 801, ppid: 800, path: "/bin/zsh", args: [])
        let unsigned = ResponsibleAppIdentity(
            name: "Unsigned", bundleID: "example.unsigned", teamID: nil,
            signing: .unsigned, path: "/Applications/Unsigned.app"
        )

        let result = tree.responsibleApp(
            actorPID: 801, responsiblePID: 800,
            resolver: Resolver(identities: [800: unsigned])
        )

        XCTAssertEqual(result.metadata["responsibleAppSigning"], "Unsigned")
        XCTAssertEqual(result.metadata["responsibleAppBundleID"], "example.unsigned")
    }

    private var chatGPTIdentity: ResponsibleAppIdentity {
        ResponsibleAppIdentity(
            name: "ChatGPT", bundleID: "com.openai.chat", teamID: "2DC432GLL2",
            signing: .signed, path: "/Applications/ChatGPT.app"
        )
    }
}
