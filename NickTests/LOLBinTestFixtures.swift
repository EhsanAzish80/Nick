import Foundation
@testable import Nick

enum LOLBinTestFixtures {
    static func curlPipeEvent(pid: Int32) -> ESEvent {
        ESEvent(
            eventType: .authExec,
            processPath: "/Applications/Terminal.app/Contents/MacOS/Terminal",
            pid: pid,
            parentPid: 1,
            filePath: "/bin/sh",
            decision: .allow,
            threat: .init(
                threatName: "Download-to-shell command detected",
                threatFamily: "lolbin-behavior",
                isCodeSigned: true,
                teamID: "APPLE_PLATFORM",
                signingID: "com.apple.sh",
                metadata: [
                    "reason": "curl_pipe_shell",
                    "rule": "curl_pipe_shell",
                    "ruleTier": "protected",
                    "detectionKind": "lolbin-behavior",
                    "signalSeverity": "critical",
                    "execTargetPath": "/bin/sh"
                ]
            )
        )
    }
}
