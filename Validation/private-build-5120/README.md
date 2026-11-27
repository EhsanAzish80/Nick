# Private 5.1.7 candidate, build 5120

This is an installed-test candidate, not public release approval. Build with `PrivateTest.xcconfig`; all components must have build 5120. The existing private label is enabled. The old synthetic worker-delay admission requires build 5118 and cannot arm on 5120; no delay configuration is created. No appcast or website update.

## Source and local evidence

The integrated source passed all 1,120 tests through Xcode on the Mac Studio on 2026-11-27. A final finding-only scheduling safeguard then passed all 32 incident-ingestion tests, including its new non-finding admission regression; its current-head CI is a separate gate. Zero failures/skips; 11 existing runtime warnings remain in direct synchronous-constructor tests. Full xcresult and SHA-256 manifest are preserved locally under ignored `build/IssueValidation/5.1.7-integrated/`.

The source includes independently scoped PRs for GUI activity/activation, canary-copy renames, simulator/XCTest resource finalization, FileProvider backup names, host MobileAsset and CloudDocs resources, shell execution evidence, off-main finding signature resolution, durable notification-count refresh, and scoped termination-report diagnostics. WhatsApp ownership/updater and SSH PRs also add conservative regression coverage; they do not establish the cause of their historical fallthroughs.

## Installed checks after installation

Do not start until Nick.app, Endpoint Security and Network Filter all report 5120. Preserve current Strict Mode and emergency settings. Keep evidence local and redact identifiers before any later public report.

1. Verify all three build identities, active sensor health, settings consistency and scoped historical/current-process report labels.
2. Open the main window from menu bar, Dock and a notification; verify prompt first render and preserved alert selection. Reopen from minimized/hidden state.
3. Open WhatsApp normally and check for new own-cookie denies. Observe a real updater transition only if available; do not force an update or weaken staged-bundle validation.
4. During an ordinary Time Machine backup, check that moving backup copies of canaries does not produce a new ransomware incident. Live deployed-canary protection remains independently covered by tests.
5. Exercise the simulator GeoServices and XCTest SpringBoard cache flows during normal simulator/test use; no broad simulator exclusions exist.
6. Observe normal WhatsApp/FileProvider and CloudDocs propagation. MobileAsset finalization may require naturally occurring work; absence of that workload is pending coverage, not a pass.
7. Use disposable synthetic keys for Git signing and ssh-add recognition. Do not use or collect real key contents. Record recognition evidence if generic review recurs.
8. Run a benign temporary-output workspace diff. Explicit payload invocation remains covered by the positive Xcode regressions.
9. Verify Notification Center updates a repeated protected incident count silently after durable persistence, preserving its ID and banner throttle; acknowledge or remove the notification afterward.
10. Perform a short, bounded Diagnostics refresh/ingestion check and review warning output. No new multi-day soak or full scorecard run is planned.

For any later necessary backup fixture, keep the standing 1 GiB extension footprint ceiling, 50 GiB free-disk floor and existing swap safeguards. Passive kernel measurements only; do not attach heap/leaks/vmmap/footprint/sample to the ES extension.

## Claims still open

The historical full Backblaze/remote Time Machine workload and spontaneous deadline-kill cause (#122) are not proven resolved. #129/#130/#137 need installed evidence of their original fallthrough conditions. #51 does not establish the cause of every historical warning or UI stall. Unit tests, CI, signed/notarized package and installed results remain separate gates. Keep the original issues open pending the relevant evidence.
