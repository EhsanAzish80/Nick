# Outreach copy

These are approval-ready drafts. Recheck each channel's live rules and edit for
the actual artifact before publishing.

## Mac Admins Slack — `#oss-announce`

> I build Nick, an open-source local security and diagnostics app for macOS.
> Version 4.6.2 now opens in a simpler Home / Scan / Activity / Protection view,
> while Advanced mode keeps Runtime Compare, process, persistence, network, and
> rule evidence. The other focus was reducing noisy findings from signed apps,
> developer builds, package caches, and broad YARA heuristics; CI now includes a
> benign-corpus gate. Nick is not MDM or a fleet EDR—I’m especially interested
> in whether its local Runtime Compare/export workflow is useful during install,
> VPN, or extension troubleshooting. Source and release: [tagged link]

Follow-up question for prior feedback:

> Earlier feedback asked for flexible export/logging destinations. Before I add
> another output path, which is actually useful in your environment today:
> local JSON, CEF/syslog, or a documented HTTP webhook? Concrete redaction and
> retention requirements would help more than votes.

## Hacker News — Show HN

Title:

> Show HN: Nick – open-source, local-first macOS security with explainable alerts

Body:

> I built Nick because Mac security tools often make users choose between a
> simple black box and several separate technical utilities. Nick combines local
> YARA scanning, Endpoint Security events, conservative behavioral correlation,
> system checks, and a before/after Runtime Compare workflow.
>
> The latest release has two views: Simple presents one protection state and
> plain-language actions; Advanced exposes the underlying process, persistence,
> network, and rule evidence. The difficult part has been false positives, so
> heuristic matches remain reviewable and the CI suite scans a large benign macOS
> corpus before release.
>
> It is AGPL-3.0, requires macOS 26+, and the signed/notarized build is free. I’d
> value criticism of the trust boundaries and verdict policy more than feature
> requests: [tagged link]

## r/MacApps — only after eligibility check

Title:

> [OS] Nick 4.6.2 — local Mac security with a new Simple mode (Free)

Body:

> I’m Nick’s developer. It helps you see whether important Mac protections are
> working, scan apps and files locally, and understand alerts without uploading
> your activity.
>
> Compared with using several separate diagnostic utilities, Nick puts scanning,
> protection status, quarantine, and recent activity in one native interface;
> unlike a managed commercial EDR, it is open source and local, but it does not
> provide fleet management or promise to catch every threat.
>
> Price: free, AGPL-3.0. macOS 26+, Apple Silicon and Intel. Source, notarized
> download, privacy details, and changelog: [tagged link]

Before posting: confirm 10+ local karma, rule acknowledgement, the 30-day
developer cooldown, correct `[OS]` prefix and Free flair, and the current
trust/transparency requirements.

## LinkedIn

> The hardest part of a security alert is often not detection—it is knowing when
> *not* to make a scary claim.
>
> In Nick 4.6.2 I separated the interface into Simple and Advanced views, but the
> more important work is underneath: signed-app context, developer-build
> recognition, rule metadata, and a benign-corpus CI gate. A heuristic can ask
> for review without pretending it proved malware.
>
> I wrote up the architecture, the trade-offs, and the cases that changed the
> policy: [tagged article link]
>
> I build Nick; it is free and open source.

## X

> Nick 4.6.2 is simpler on the surface and more careful underneath: a new Simple
> mode, full evidence in Advanced mode, live Deep Scan discovery, and a
> benign-corpus gate for noisy rules. Free, local-first, open source. I build it:
> [tagged link]

## Technical article pitch

Subject: A measured macOS false-positive case study with reproducible rules

> I maintain Nick, an open-source macOS security project. I have a technical
> write-up showing how broad behavior rules misclassified SwiftPM artifacts,
> signed updaters, and developer workflows, then how context and a benign-corpus
> gate changed the verdicts without suppressing concrete signatures. It includes
> code links, limitations, and exact test counts. Would this fit your readers? I
> can send the draft; no exclusivity or paid placement requested.

