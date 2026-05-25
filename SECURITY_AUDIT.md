# Nick — Security Audit Log

Running record of security findings, root-cause analyses, and fixes applied during development.

---

### 4.7 Supply-Chain Bypass in Trust Downgrade (Fixed)

**Finding:** `applyTrustedDowngrade` could downgrade a mixed-source alert 
containing persistence signals when a trusted process (e.g., VS Code's 
"Code Helper") was also in the correlation window.

**Attack scenario:** A compromised VS Code extension drops a malicious 
LaunchAgent (persistence signal, .high) while simultaneously spawning 
shells (process signal, .high, attributed to trusted "Code Helper"). 
The `multipleHighSignalsRule` fires with both signals. Before the fix, 
`applyTrustedDowngrade` saw the trusted Code Helper fraction and 
downgraded the entire alert to .medium — potentially below the 
notification threshold, silently hiding the persistence attack.

**Fix:** Early-return guard in `applyTrustedDowngrade`: if any 
contributing signal has `source == .persistence`, return the alert 
unmodified at full severity. No trust downgrade is ever applied to 
alerts involving persistence mechanisms.

**Severity:** High
**Status:** Fixed
