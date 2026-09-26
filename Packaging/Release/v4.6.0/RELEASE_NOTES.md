# Nick 4.6

Nick 4.6 strengthens malware detection while keeping legitimate developer and
system activity quiet.

## Highlights

- Adds vetted, credited signatures for macOS malware families and
  cross-platform implants.
- Applies stronger execution trust checks to ad-hoc code and binaries launched
  from staging or persistence locations.
- Adds rename-burst and document-canary ransomware detection.
- Uses one context-aware verdict policy across Deep Scan, downloads, removable
  media, disk images, and real-time monitoring.
- Checks known-malware hashes before an unknown binary's first launch.
- Improves scan throughput and reduces noisy developer, cache, and email
  findings.

## Verification

- 443 automated tests executed: 439 passed, 4 platform-dependent tests skipped,
  and 0 failed.
- The optimized app and every shipping helper and extension build successfully
  and report version 4.6, build 427.
- All 80 bundled YARA rules compile and pass metadata validation.
- A benign corpus of 7,540 executable candidates produced zero
  malware-family/signature matches.
- The installer package and disk image are Developer ID signed, Apple
  notarized, stapled, and accepted by Gatekeeper.

Nick requires macOS 26 or later. Existing users can update through Nick's
built-in updater after the 3NSofts appcast is published.
