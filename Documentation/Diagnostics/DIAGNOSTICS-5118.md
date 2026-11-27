# Private diagnostic 5118

This build corrects only synthetic worker-delay admission from private 5117.
The installed 5117 retry admitted zero delays and is not watchdog validation.
Its raw evidence and summary remain preserved in the 5117 archive.

The hook confused CS_LINKER_SIGNED (0x00020000) with CS_SIGNED
(0x20000000). The shared predicate now uses named masks and tests the
actual Developer ID helper flags (0x22011311), missing validity, ad-hoc
signing, and linker-only signing. EventHandler calls that same predicate.

Admission remains pinned to build 5118 and helper signing ID
com.3nsofts.diagnostics.Watchdog5118. All other root ownership, exact
cdhash/path, expiry, nonce, single-active and lifetime limits from
DIAGNOSTICS-5117.md remain unchanged. No normal trust policy or protection
verdict changes. No control file is installed in the package.

Installed watchdog validation remains pending until both synthetic paths
show an admitted/completed delay and a successful watchdog response.
