# Private 5118 validation closeout — November 22, 2026

This closes the local validation checklist; it does not close issue #122 or authorize a merge or release. The user requested one final bounded SMB capture and no additional test cycle. Remaining uncertainties are review items, not an automatically expanding test plan.

## Exact build and tests

Private 5.1.5/5118 is built from `89fabca2cb4ccbdba61e9084015544b0d60042da`. The app and both active extensions were verified at 5118. The installer is signed, notarized, stapled and Gatekeeper accepted. Exact source, both-architecture matching dSYMs, package, Xcode result bundle and checksums are retained locally. No private download links or raw diagnostics are included here.

The Xcode-launched full suite passed **1,091 tests**, zero failures/skips. Thirteen main-thread runtime warnings remain recorded. The private-only helper admission corrects CS_LINKER_SIGNED versus CS_SIGNED and tests the actual signed-helper flags. Normal trust/revocation/expiry and enforcement decisions are unchanged.

## Installed synthetic watchdog integration — complete

The five-minute passive capture used only disposable, exactly signed/hash-pinned helpers and synthetic credential files. No real credentials, profiler attachment, settings changes or extension suspension were used. A root-owned expiring control, one-active-delay limit and lifetime admission cap bound the diagnostic hook.

| Case | Injected / completed delays | Watchdog wins | Response errors / late attempts |
| --- | ---: | ---: | ---: |
| Unarmed control | 0 / 0 | 0 | 0 / 0 |
| Credential worker | 1 / 1 | 1 | 0 / 0 |
| Prelaunch worker | 1 / 1 | 1 | 0 / 0 |

Both workers slept for three seconds while the independent watchdog submitted the existing fallback. At the end, no AUTH or injection remained pending, no duplicate submissions/capacity overflows were recorded, settings matched, no new termination reports appeared, and the control file was removed. Across 299 passive samples, peak footprint was **62.9 MiB**, final **48.7 MiB**. Evidence was copied and hash-verified.

The repeat under a warm cache is not independent proof of nonce rejection; the pure admission tests cover that condition. Worker sleep proves watchdog integration under these bounded delays, not the cause of historical kills or arbitrary Security API behavior.

## Final bounded SMB capture

Completed the one authorized capture, with **691 passive samples**. The retained app-like SMB scan completed **737 entries / 552 files in 277.02 seconds**. Sampled peak footprint was **100.8 MiB**, final **94.0 MiB**. It stayed below the 1 GiB ceiling but did not return to the starting footprint in the bounded observation. The same process and settings survived; there were **zero new termination reports, response errors or late attempts**, zero pending AUTHs, duplicate submissions or capacity overflows at the end. Mount, server and relay cleanup completed normally. The synthetic control remained absent and evidence was copied/hash-verified.

| Window | Mean whole-extension CPU | Delivered callbacks/s | Process-global streaming hash bytes |
| --- | ---: | ---: | ---: |
| Baseline | 40.4% | 21,027 | 179,847,680 |
| SMB plus recovery | 26.4% | 6,396 | 2,261,956,348 |
| Final baseline | 51.0% | 14,067 | 74,895,920 |

The active scan itself averaged 33.6% whole-extension CPU. These are not reader-thread CPU numbers. Background cloud activity was present in every phase, and process-global hash bytes can include unrelated scanning. The measurements establish bounded completion on this fixture, not a causal CPU improvement.

Both callback histories were preserved. Primary callback count increased by 7,092,108 with no sequence mismatches, lookup failures, newly threshold-qualified callback records or overwrites. The shell-profile client delivered no callbacks during this capture; its empty history is not a coverage claim. Slow-response history was unchanged, including the earlier synthetic watchdog timings; those old records are not new slow responses from this scan.

The passive thread collector produced 691 samples without API errors, but its enumerated identifiers did not match the 47 callback identifiers. No callback-thread CPU attribution is valid from that result; empty per-thread phase summaries are **unavailable**, not zero CPU. This measurement limitation remains documented without another test cycle.

Limits remained 1 GiB footprint, 50 GiB disk, +1 GiB swap and the existing available-memory guard. No profiler attachment, protection-setting or scan-policy changes. Local archive reference: `5118-89fabca2cb4ccbdba61e9084015544b0d60042da/cpu-comparison-NickBackupRepro-20261122-202109`.

All four remote PR checks were verified passing at head `c2857e24280e873c4e2f98b1c0a3483addaf7faa`. This does not apply remote CI to the two newer local private-diagnostic commits.

## Decision boundaries

- Proven local fixes: credential-attribution trust storm; creation-history CPU hotspot; streaming hash autorelease retention; response ownership and independent watchdog integration.
- The reporter's historical kernel terminations remain unattributed. Synthetic loopback SMB is not the complete remote Time Machine/Backblaze workload.
- A callback-associated thread's CPU includes any other work on that thread. Whole-extension CPU must not be called reader CPU.
- Historical report-counter semantics, USB completed-record eviction, mount scheduling and long-duration write budget remain separately tracked follow-ups.
- PR CI applies only to its exact tested head. The local private diagnostic commits do not inherit a remote CI pass.
- No further local test cycle is planned in this closeout. No merge, public package, appcast or website change is authorized.
