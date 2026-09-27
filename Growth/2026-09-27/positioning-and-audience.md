# Positioning and audience report

## Recommended position

**Nick is open-source, local-first Mac security that makes advanced monitoring
understandable. It checks apps and files, connects behavioral evidence, and
shows what happened and what to do next—without uploading activity to a hosted
analysis service.**

The differentiator is not “more features than antivirus.” It is the combination
of inspectable detection, local processing, conservative verdicts, and two UX
depths: Simple for everyday use and Advanced for technical investigation.

## Message hierarchy

1. **Understand your Mac's protection state.** One status, direct fixes, and
   plain-language alerts.
2. **Keep evidence local.** Scanning and correlation occur on the Mac.
3. **Review before accusing.** Contextual behavior is separated from confirmed
   malware evidence.
4. **Inspect the implementation.** Source, rules, architecture, CI, and release
   checks are public.
5. **Go deeper when useful.** Advanced mode exposes process, persistence,
   network, rule, and Runtime Compare evidence.

## Primary audiences

| Audience | Job to be done | Best proof | Friction | First message |
|---|---|---|---|---|
| Privacy-conscious Mac owners | Understand whether core protections are working without cloud telemetry | Simple Home, local-processing explanation, notarized release | System-extension permissions look intimidating | “Clear Mac protection without uploading your activity.” |
| Developers | Distinguish normal build/package activity from genuinely suspicious behavior | False-positive case study, rule metadata, test corpus | Security tools often flag toolchains | “Evidence-aware scanning designed not to call every developer tool malware.” |
| Security researchers | Inspect detection logic and contribute signatures or tests | Architecture diagram, YARA provenance, negative fixtures, CI | Claims need reproducible evidence | “An auditable macOS detection lab with conservative verdicts.” |
| Mac administrators | Compare runtime state and gather local diagnostic evidence | Runtime Compare support bundle and sensor-health reporting | Nick is not MDM, EDR fleet management, or compliance certification | “A local troubleshooting companion—not a fleet control plane.” |

## Audience priority for this cycle

1. Developers who use Homebrew, Xcode, SwiftPM, npm, Python, Docker, or security tools.
2. Privacy-conscious technical Mac owners.
3. Security researchers interested in macOS rules and false-positive testing.
4. Mac administrators, approached through Runtime Compare and open-source
   diagnostics rather than an antivirus pitch.

Developers are first because the 4.5–4.6 work supplies unusually concrete proof:
structured build artifacts, signed software context, and a benign-corpus gate.
That is a sharper story than a general “free security app” claim.

## Claims to avoid

- “Complete protection,” “catches every threat,” or “replacement for an EDR.”
- “Zero false positives” or a percentage without a defined corpus and method.
- “AI-powered antivirus” as the lead; Foundation Models are optional explanation,
  not the core verdict authority.
- Compliance, hardening enforcement, or fleet visibility claims.
- Comparing competitors with unverified checkmark tables.

## Success definition after three weeks

- At least two channels produce identifiable qualified visits.
- Release downloads increase over the pre-cycle baseline without repeated posting.
- At least three pieces of useful feedback or one external issue/PR is received.
- The README-to-download path and first-run explanation have no known stale or
  contradictory copy.

