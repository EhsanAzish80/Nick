# Nick 4.2

Build 420 improves detection accuracy, alert usefulness, and quarantine safety.

## Clearer alerts

- Attributes developer commands to the parent app when evidence is available.
- Explains common shell, build, SSH, Git, and download workflows without treating the tool name itself as malware.
- Describes broad rule matches in signed installed software as review items rather than confirmed malware.
- Shows green, orange, or red menu bar state based on whether protection is healthy, needs review, or needs immediate attention.

## Detection accuracy

- Requires stronger command, parent, signing, path, or network evidence for reverse-shell and living-off-the-land escalation.
- Recognizes application-managed encrypted cache activity and requires corroborating ransomware behavior before quarantine.
- Prevents WhatsApp encrypted media-cache writes from being quarantined solely for high entropy.
- Distinguishes missing persistence executables from unsigned or malicious executables.

## Quarantine and remediation safety

- Validates evidence hashes before quarantine.
- Preserves identical samples as separate records instead of overwriting evidence.
- Never deletes the original file when quarantine fails.
- Handles disappeared or changed files safely during alert actions, restore, and remediation.

## Verification

- 373 automated tests executed: 369 passed, 4 platform-dependent tests skipped, and 0 failed.
- Nick, NickExtension, NickNetFilter, and Nick Uninstaller all report version 4.2, build 420.
- The installer package and disk image are Developer ID signed, notarized, stapled, and accepted by Gatekeeper.

## Requirements

- macOS 26 or later.
- User approval for the Endpoint Security and Network Extensions.
- Full Disk Access for Nick and NickExtension.
