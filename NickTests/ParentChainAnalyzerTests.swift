// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

// MARK: - ParentChainAnalyzerTests

final class ParentChainAnalyzerTests: XCTestCase {

    // MARK: - Helpers

    private func makeProc(
        pid: Int32,
        name: String,
        parentPID: Int32 = 1
    ) -> NickProcessInfo {
        NickProcessInfo(
            pid: pid, path: "/usr/bin/\(name)", name: name,
            parentPID: parentPID, parentName: "",
            signingStatus: .signed(teamID: "APPLE"), user: "user", startTime: Date()
        )
    }

    // MARK: - buildChain

    func test_buildChain_singleProcess_depthOne() {
        let proc = makeProc(pid: 100, name: "bash")
        let chain = ParentChainAnalyzer.buildChain(for: proc, allProcesses: [proc])
        XCTAssertEqual(chain.depth, 1)
    }

    func test_buildChain_threeHops_correctDepth() {
        let grandparent = makeProc(pid: 1,   name: "launchd",  parentPID: 0)
        let parent      = makeProc(pid: 500, name: "Safari",   parentPID: 1)
        let child       = makeProc(pid: 600, name: "bash",     parentPID: 500)
        let all = [grandparent, parent, child]
        let chain = ParentChainAnalyzer.buildChain(for: child, allProcesses: all)
        XCTAssertEqual(chain.depth, 3)
        XCTAssertEqual(chain.root?.name, "launchd")
        XCTAssertEqual(chain.leaf?.name, "bash")
    }

    func test_buildChain_cycleDetected_doesNotLoop() {
        // Artificial cycle: proc A has parent B, B has parent A
        let a = NickProcessInfo(pid: 10, path: "/a", name: "a", parentPID: 20, parentName: "",
                                signingStatus: .adHoc, user: "u", startTime: Date())
        let b = NickProcessInfo(pid: 20, path: "/b", name: "b", parentPID: 10, parentName: "",
                                signingStatus: .adHoc, user: "u", startTime: Date())
        let chain = ParentChainAnalyzer.buildChain(for: a, allProcesses: [a, b])
        XCTAssertLessThanOrEqual(chain.depth, 3) // must not loop forever
    }

    func test_buildChain_missingParent_stopsAtKnownAncestor() {
        let parent = makeProc(pid: 300, name: "Finder",    parentPID: 999) // 999 not in list
        let child  = makeProc(pid: 400, name: "python3",   parentPID: 300)
        let chain = ParentChainAnalyzer.buildChain(for: child, allProcesses: [parent, child])
        XCTAssertEqual(chain.depth, 2)
    }

    // MARK: - evaluateChain — browser → shell

    func test_evaluateChain_browserToShell_returnsCriticalSignal() {
        let browser = makeProc(pid: 100, name: "Safari",   parentPID: 1)
        let shell   = makeProc(pid: 101, name: "bash",     parentPID: 100)
        let all = [browser, shell]
        let chain = ParentChainAnalyzer.buildChain(for: shell, allProcesses: all)
        let signal = ParentChainAnalyzer.evaluateChain(chain)
        XCTAssertNotNil(signal)
        XCTAssertEqual(signal?.severity, .critical)
        XCTAssertEqual(signal?.metadata["reason"], "browser_to_shell")
    }

    func test_evaluateChain_browserToInterpreter_returnsCriticalSignal() {
        let browser = makeProc(pid: 100, name: "Google Chrome", parentPID: 1)
        let interp  = makeProc(pid: 102, name: "python3",       parentPID: 100)
        let chain   = ParentChainAnalyzer.buildChain(for: interp, allProcesses: [browser, interp])
        let signal  = ParentChainAnalyzer.evaluateChain(chain)
        XCTAssertNotNil(signal)
        XCTAssertEqual(signal?.severity, .critical)
    }

    // MARK: - evaluateChain — office → shell

    func test_evaluateChain_officeToShell_returnsCriticalSignal() {
        let word  = makeProc(pid: 200, name: "Microsoft Word", parentPID: 1)
        let shell = makeProc(pid: 201, name: "zsh",            parentPID: 200)
        let chain = ParentChainAnalyzer.buildChain(for: shell, allProcesses: [word, shell])
        let signal = ParentChainAnalyzer.evaluateChain(chain)
        XCTAssertNotNil(signal)
        XCTAssertEqual(signal?.metadata["reason"], "office_to_shell")
    }

    func test_evaluateChain_excelToOsascript_returnsCriticalSignal() {
        let excel  = makeProc(pid: 300, name: "Microsoft Excel", parentPID: 1)
        let script = makeProc(pid: 301, name: "osascript",       parentPID: 300)
        let chain  = ParentChainAnalyzer.buildChain(for: script, allProcesses: [excel, script])
        let signal = ParentChainAnalyzer.evaluateChain(chain)
        XCTAssertNotNil(signal)
        XCTAssertEqual(signal?.severity, .critical)
    }

    // MARK: - evaluateChain — PDF viewer → shell

    func test_evaluateChain_previewToShell_returnsCriticalSignal() {
        let preview = makeProc(pid: 400, name: "Preview", parentPID: 1)
        let shell   = makeProc(pid: 401, name: "bash",    parentPID: 400)
        let chain   = ParentChainAnalyzer.buildChain(for: shell, allProcesses: [preview, shell])
        let signal  = ParentChainAnalyzer.evaluateChain(chain)
        XCTAssertNotNil(signal)
        XCTAssertEqual(signal?.metadata["reason"], "pdf_to_shell")
    }

    // MARK: - evaluateChain — deep shell nesting

    func test_evaluateChain_deepShellNesting_returnsHighSignal() {
        let s1 = makeProc(pid: 500, name: "bash", parentPID: 1)
        let s2 = makeProc(pid: 501, name: "sh",   parentPID: 500)
        let s3 = makeProc(pid: 502, name: "zsh",  parentPID: 501)
        let chain = ParentChainAnalyzer.buildChain(for: s3, allProcesses: [s1, s2, s3])
        let signal = ParentChainAnalyzer.evaluateChain(chain)
        XCTAssertNotNil(signal)
        XCTAssertEqual(signal?.metadata["reason"], "deep_shell_nesting")
        XCTAssertEqual(signal?.severity, .high)
    }

    // MARK: - evaluateChain — trusted parent suppression

    func test_evaluateChain_trustedRootSuppressesSignal() {
        let terminal = NickProcessInfo(
            pid: 600, path: "/Applications/Utilities/Terminal.app", name: "Terminal",
            parentPID: 1, parentName: "",
            signingStatus: .signed(teamID: "APPLE"), user: "user", startTime: Date()
        )
        let shell = makeProc(pid: 601, name: "bash", parentPID: 600)
        let chain = ParentChainAnalyzer.buildChain(for: shell, allProcesses: [terminal, shell])
        let signal = ParentChainAnalyzer.evaluateChain(chain)
        XCTAssertNil(signal)
    }

    // MARK: - evaluateChain — safe chain

    func test_evaluateChain_finderToTextEdit_returnsNil() {
        let finder   = makeProc(pid: 700, name: "Finder",   parentPID: 1)
        let textedit = makeProc(pid: 701, name: "TextEdit", parentPID: 700)
        let chain = ParentChainAnalyzer.buildChain(for: textedit, allProcesses: [finder, textedit])
        let signal = ParentChainAnalyzer.evaluateChain(chain)
        XCTAssertNil(signal)
    }

    // MARK: - signals(from:)

    func test_signals_browserToShellInSnapshot_returnsCriticalSignal() {
        let browser = makeProc(pid: 800, name: "Firefox", parentPID: 1)
        let shell   = makeProc(pid: 801, name: "bash",    parentPID: 800)
        let signals = ParentChainAnalyzer.signals(from: [browser, shell])
        XCTAssertFalse(signals.isEmpty)
        XCTAssertEqual(signals.first?.severity, .critical)
    }

    func test_signals_noSuspiciousProcesses_returnsEmpty() {
        let procs = [makeProc(pid: 900, name: "Finder"), makeProc(pid: 901, name: "Safari")]
        let signals = ParentChainAnalyzer.signals(from: procs)
        XCTAssertTrue(signals.isEmpty)
    }

    func test_signals_chain_containsDetectorMetadata() {
        let browser = makeProc(pid: 1000, name: "Arc",  parentPID: 1)
        let shell   = makeProc(pid: 1001, name: "bash", parentPID: 1000)
        let signals = ParentChainAnalyzer.signals(from: [browser, shell])
        XCTAssertEqual(signals.first?.metadata["detector"], "ParentChainAnalyzer")
    }

    func test_signals_chainStringIncludesAllNames() {
        let browser = makeProc(pid: 1100, name: "Brave Browser", parentPID: 1)
        let shell   = makeProc(pid: 1101, name: "sh",            parentPID: 1100)
        let signals = ParentChainAnalyzer.signals(from: [browser, shell])
        let chain = signals.first?.metadata["chain"] ?? ""
        XCTAssertTrue(chain.contains("Brave Browser"))
        XCTAssertTrue(chain.contains("sh"))
    }
}
