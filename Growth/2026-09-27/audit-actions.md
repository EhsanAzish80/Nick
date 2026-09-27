# Funnel audit and actions

## Executive finding

Nick has strong technical proof but historically led with the breadth of its
subsystems. Version 4.6.2 supplies a better entry point: clear everyday status
first, inspectable evidence second. The funnel should mirror that order.

## README

### Observed

- Strong trust signals: CI, Sonar, Codecov, license, architecture, permissions,
  responsible disclosure, and precise limitations.
- The installation section still named 4.6/build 427 after 4.6.2 shipped.
- A new visitor had to read substantial architecture before learning about
  Simple mode.
- No first-five-minutes expectation or direct false-positive escape route near
  installation.

### Implemented in this cycle

- Updated the stable release to 4.6.2/build 429.
- Added Simple/Advanced positioning before the feature inventory.
- Added honest non-guarantee language and a first-five-minutes checklist.
- Linked the dedicated false-positive form near setup guidance.

### Next asset

Add one compressed real screenshot or short GIF only after it is captured from
the released build and remains readable on GitHub mobile widths.

## Website

### Observed

- The page has release metadata, direct download, integrity hash, source link,
  privacy positioning, and detailed capabilities.
- The hero headline “See what changed. Prove what did not.” primarily describes
  Runtime Compare, not the new default experience.
- “Full antivirus” appears in conversion copy despite the FAQ's more accurate
  statement that no tool guarantees every threat.
- Feature density makes it difficult to distinguish the first user outcome from
  advanced diagnostics.

### Implement in this cycle

- Lead with “Understand what your Mac is doing” and local, explainable protection.
- Replace “full antivirus” with “local security monitoring and scanning.”
- Put Simple/Advanced proof before the complete feature tour.
- Keep the notarized download, source, checksum, and macOS requirement together.

## Onboarding

### Observed

- Permission sequencing and explicit macOS approvals are sound.
- The welcome grid used subsystem terms such as Process Monitor, Network
  Watchdog, Persistence Watch, YARA Scanner, and AI Scoring.
- This contradicted the simpler default introduced in 4.6.2.

### Implemented in this cycle

- Reduced the welcome grid to four outcomes: check new apps, scan the Mac,
  explain alerts, and verify Mac settings.
- Preserved the Simple/Advanced explanation and explicit permission note.

## Download and trust flow

### Observed

- GitHub DMG, direct website PKG, Sparkle appcast, SHA-256, Developer ID,
  notarization, and AGPL source are all available.
- The website CTA downloads from GitHub while Sparkle uses the site-hosted PKG;
  this is valid but should be explained consistently.
- GitHub download counts omit the direct website PKG and cannot measure update
  adoption by themselves.

### Action

- Use tagged website URLs for campaigns; keep artifact URLs untagged and stable.
- Measure GitHub DMG downloads separately from direct PKG/appcast requests.
- Treat update adoption as unavailable unless privacy-preserving aggregate edge
  counts can be obtained; do not add per-device analytics merely for growth.

## Baseline interpretation

- 18 stars, 0 forks, 1 subscriber, and 0 open issues.
- GitHub's available 14-day window reports 69 views / 20 unique visitors and 39
  clones / 34 unique cloners.
- Referrers are sparse: GitHub 18/11 unique, LinkedIn 2/1, 3NSofts 1/1, X 1/1.
- Historical GitHub release assets have 55 downloads in total at capture time;
  4.6.2 began at zero immediately after release.
- These are directional small-sample baselines, not conversion conclusions.

