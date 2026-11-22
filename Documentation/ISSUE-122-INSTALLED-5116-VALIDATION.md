# Installed private 5116 validation — November 22, 2026

The app and both active system extensions were verified as 5.1.5/5116. The signed, notarized installer uses source commit `c0146ecf899e17297061fc8708755520c1a3deea`; exact source and matching arm64/x86_64 dSYMs are archived locally. This is not a public release.

## Scope and safeguards

Three captures used passive kernel accounting and protected local health snapshots, with no profiler attachment, extension suspension, protection-setting change, or real credential reads. Limits remained: 1 GiB extension footprint, 50 GiB minimum free disk, +1 GiB swap and the existing 512 MiB available-memory proxy. The matched SMB test verified Xcode was closed and swap was stable. The synthetic SMB server was host-internal, loopback only, limited to 512 MiB/two CPUs, and the relay retained the existing 6 MiB/s limit. Real backup destinations were not modified.

All captures completed normally, settings hashes matched, the same extension process survived, no new extension termination reports appeared, and no mounts remained after cleanup. Raw local evidence was copied and hash-verified into the 5116 diagnostic archive. Private paths, host identifiers, and the private installer link are intentionally omitted here.

## Results

| Capture | Passive samples | Sampled peak footprint | Final footprint | Mean extension CPU, one-core scale |
| --- | ---: | ---: | ---: | ---: |
| Baseline | 121 | 33.8 MiB | 33.8 MiB | 19.7% |
| SMB scan plus recovery | 440 | 53.4 MiB | 35.0 MiB | 38.8% |
| Cold signed readers plus recovery | 121 | 48.3 MiB | 41.6 MiB | 41.7% |

The unchanged app-like SMB image completed **737 entries / 552 scanned files in 278.99 seconds**, followed by 120 seconds recovery. The process lifetime peak was 53.5 MiB (baseline lifetime peak 46.3 MiB). The comparable 5115 scan took 300.24 seconds; its observed window peak was 113.6 MiB and final footprint 94.1 MiB. These are bounded comparisons under ordinary desktop activity, not isolated causal CPU or memory benchmarks.

No new >=100 ms slow-response records or threshold-qualified full-callback records appeared since the completed baseline; overwrite and sequence-mismatch counts did not increase. Response errors and late attempts remained zero. Pending AUTHs ended at zero, with process peak pending four, no diagnostic-capacity overflow, no accidental duplicate submissions and no recovery retries.

Eight distinct Developer ID-signed synthetic readers each read a harmless scratch keychain fixture 20 times (160 successful reads). The reader window recorded eight distribution-cache misses and eight credential deferrals, plus nine prelaunch deferrals (eight reader launches and another operation during the window). All completed through the worker path, with no in-flight work left. Watchdogs were scheduled but **none fired or won**; no runtime fault injection was enabled. Real credential data was never accessed.

## What this establishes, and what remains open

The installed allocation cleanup stays bounded on the retained streaming fixture that previously crossed the memory ceiling. Normal installed deferred AUTH paths complete after the response-ownership change. The same production coordinator and dedicated scheduler passed stalled-worker, racing-response, cancellation and bounded same-verdict recovery tests in Xcode; the full suite passed 1,084 tests with zero failures/skips before packaging.

This does **not** reproduce a slow Security validation or force a watchdog win in the installed extension. It does not prove the cause of historical ENDPOINTSECURITY kills, the reporter's complete 15 GiB workload, or long-duration write-budget compliance. The provisional CPU goal below 30% refers to the reader thread. These measurements are whole-extension CPU and do not establish whether that thread-specific goal was achieved; background activity also prevents assigning the total cost to a specific change. Further CPU attribution needs its own measured experiment, not a speculative change.

The historical kernel-report count is still a disk-history count, not current-build kill count. Completed USB-record eviction is not fully described by its existing overflow metric. These diagnostic limitations, mount-scan scheduling policy and write-budget follow-up remain explicit review items. No broad backup-app exclusion, trust-policy change, scan-policy reduction or timeout-policy change is justified by these captures.

No merge or release is requested. Issue #122 remains open.
