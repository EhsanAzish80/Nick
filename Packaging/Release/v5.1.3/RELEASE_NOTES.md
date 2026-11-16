# Nick 5.1.3 — emergency extension reliability fix

Release: **5.1.3 (5104)** for macOS 26 and later.

## Fixed

- Remove filesystem-aware URL construction from high-frequency file-open credential checks, tamper path matching and platform-process name checks. Kernel-provided vnode paths are classified lexically; explicit scan registrations still resolve their scope before authorization.
- Drain temporary Foundation objects for every Endpoint Security callback and each deferred queue work item, avoiding accumulation across a continuously busy callback queue.
- Batch unchanged routine review-tier incident recurrences instead of repeatedly rewriting the complete incident snapshot. First findings, actionable escalation/reopening, unconfirmed actionable evidence and protected evidence remain urgent; acknowledgements still require durable persistence.

No backup-app exclusion was added. Credential, tamper and ransomware protection rules remain enabled.

## Validation and limits

Both the installer and its disk image are signed and notarized. The signed installer payload passed YARA checks across all 11 executables. Repository validation and 52 Python tests passed.

1,006 Swift tests passed, including a bounded 50,000-open classification replay and credential, tamper, scan-scope and persistence regression tests. An optimized standalone comparison of 100,000 ordinary path classifications took 1.63 seconds before the patch and 1.47 seconds after it on the development Mac; peak RSS was approximately 5.7 and 5.8 MiB respectively. These are helper measurements, not installed extension deadline or Backblaze memory measurements.

This patch addresses concrete callback allocation/path-resolution and incident-write amplification issues identified while investigating [issue #122](https://github.com/EhsanAzish80/Nick/issues/122). The reporter's exact Backblaze workload has not been reproduced locally, and full resolution of that workload requires confirmation. No additional soak or installed scorecard was run.

Thanks to **prismatic7** for the detailed crash, event-rate and memory diagnostics.
