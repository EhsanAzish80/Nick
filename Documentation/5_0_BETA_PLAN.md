# Nick 5.0 Beta Plan

The beta validates 5.0 on real Macs without changing the public appcast. This
document is preparation only; it does not authorize a tag, upload, appcast
change, website deployment, announcement, or public release.

## Channel and artifacts

- Use a separate HTTPS staging appcast and staging download location.
- Build signed, notarized PKG and DMG artifacts from a reviewed commit.
- Keep the production Sparkle feed unchanged. Release builds must never contain
  the staging URL; use the existing Debug/staging override only where intended.
- Install the first 5.0 beta manually. Shipped 4.x builds are not relied on to
  complete the transition to 5.0.
- A later 5.0 beta must update the first beta through Sparkle, including the
  application and both system extensions.

## Cohort

Start with the maintainer Mac, then a small invited set covering Apple silicon,
an Intel Mac if available, current macOS and the oldest supported macOS. Include
at least one developer workload and one ordinary non-developer workload. Do not
collect security events automatically; participants deliberately export only
the diagnostics they choose to share.

## Round sequence

1. Freeze the candidate commit and record its version, build and checksums.
2. Pass automated tests, YARA lint and the ~17k files (cap 120k) benign corpus.
3. Complete the consolidated checklist in `5_0_VALIDATION_PLAN.md` on the
   maintainer Mac.
4. Distribute the manual beta package privately with install, rollback and
   privacy instructions.
5. Run for at least seven days, including restart, sleep/wake, update, Xcode or
   equivalent heavy load, ordinary browsing, downloads and file editing.
6. Publish a higher staging build and complete the Sparkle update gate.
7. Triage every red alert, extension restart, deadline miss, lost-event count,
   update failure and user-action failure. Fix and repeat the affected gate.
8. Close the round only when the evidence record identifies the exact tested
   build and all release blockers are resolved.

## Feedback record

Record hardware/macOS, installation path, app and extension builds, runtime,
protection health, CPU/memory/energy observations, alert counts and severities,
false-positive context, update result, and whether exported diagnostics were
explicitly supplied. Strip personal paths and content before sharing review
material. Do not upload file contents, command lines, process histories or
security telemetry automatically.

## Rollback and stop conditions

Provide the last accepted signed package and uninstaller instructions. Stop a
round for extension crash/restart loops, growing deadline misses, lost normal
events, a protected finding hidden or downgraded, privileged action without
authorization, destructive remediation, or an update that leaves mixed
versions without a clear recovery message.

## Exit

At least one complete real-Mac beta round, one successful 5.0-to-later-5.0
Sparkle update, all hard gates recorded, and external-review findings fixed or
explicitly accepted are required before Phase 8 can be proposed.
