# Private build 5113 — scoped streaming read cleanup

Focused candidate for issue #122. FileScanner delegates streaming SHA-256 reads
to StreamingFileHasher, compiled into the extension and the app test host. The
reader drains an autoreleasepool after each 1 MiB chunk is accounted and hashed;
only the continuation Boolean escapes. File opening/closing, EOF/read-error
behavior, digest formatting and process-global streaming byte accounting remain
unchanged. Small-file in-memory hashing, YARA, caches, volume eligibility, limits,
trust policy and AUTH behavior are not changed.

The disposable exact-loop baseline retained ~761 MiB of Foundation read buffers
after hashing 761 MiB. The scoped replay completed all 24 retained large-file
hashes (1,248 MiB) with identical manifest SHA-256 results, ~6.8 MiB peak and
~3.9 MiB during two-minute recovery. These are helper results, not installed
5113 verification and not a complete resolution of the reporter's environment.

Xcode regression coverage exercises the same production reader at chunk/EOF
boundaries, verifies byte accounting/missing-file behavior, and hashes 288 MiB
inside one outer pool with a live-allocation growth bound. Test outcome and
signed/notarized package verification are recorded with the private archive.

Install manually, verify Nick.app and both active extensions at 5113, then reuse
the retained app-streaming fixture with the same memory/disk/swap limits and
capture natural scan completion, streaming-byte delta, footprint and recovery.
No profiler attaches to the live ES extension. No scorecard or soak is required
by this private build. Nothing is merged, publicly released or added to an
appcast/website by building this candidate.
