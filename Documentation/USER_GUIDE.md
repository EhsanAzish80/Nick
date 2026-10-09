# Nick User Guide

## First launch

Nick checks each protection independently. Setup advances only when a component
reports current health or when the user explicitly chooses to continue without
that protection.

1. Approve the Endpoint Security system extension when macOS requests it.
2. Enable Full Disk Access for both Nick and NickExtension.
3. If Scam Guardian is wanted, approve and enable Nick's Network Extension.
4. Allow notifications.
5. Let setup complete its health check.

System Settings may require Nick to be quit and reopened after Full Disk Access
changes. Nick cannot approve these switches on the user's behalf.

## Smart Scan states

- Green means the component reported current, verified health.
- Orange means setup, approval, or another action is still required.
- Red means a component failed, a required protection is unavailable, or a
  security issue was found.
- Installed does not mean active. Nick waits for a health signal from system
  extensions before marking them active.

## Alerts

An alert separates evidence from recommendation:

- Title and confidence describe the finding.
- Detected file shows the name and complete path.
- Detection identifies the matching rule when available.
- Source explains which monitor found it.
- What to do gives the safest next action.

Use Show in Finder to inspect the location. Quarantine File is available only
for an actionable file finding. Nick re-scans the file immediately before
quarantine and refuses the operation if the file changed or no longer matches.
Hide Alert removes the item from the active list without deleting a file.

Real-Time Protection can deny a known exact-hash finding within a bounded
pre-launch check. New YARA findings are normally reported after the launch or
file operation has already been allowed, so a YARA alert is evidence to review,
not a claim that execution was prevented.

Nick 5.0 development builds ship a 25-entry offline hash catalog dated October
9, 2026: 24 macOS malware indicators curated from ESET's BSD-licensed research
repository and one low-severity EICAR test entry. This small snapshot provides
day-one exact matches but does not replace current platform protections or a
maintained antivirus feed. Diagnostics shows the bundled entry count and date.
Settings → Acknowledgements shows the bundled ESET BSD-2-Clause notice.

Expected behavior can be accepted for the specific app and behavior so repeated
benign events do not create alerts. This is a local trust decision, not a global
malware exclusion.

## Scam Guardian

Scam Guardian evaluates connection hostnames. It does not read page contents,
form data, messages, or full browsing history.

Nick 4.1 observes suspected phishing destinations but does not block
connections. A finding appears in Nick for review while the application
connection remains available.

If normal browsing stops while the extension is enabled:

1. Open Nick Settings.
2. Disable Network Protection using the emergency control.
3. Confirm browsing returns.
4. Review website and app allowlists.
5. Report the affected domain and app as a false positive.

Nick's policy is fail-open when configuration is missing, stale, or invalid.
Build 416 also contains no Network Extension traffic-drop path.

## Local analysis and network access

Nick has no hosted detection service. File scanning, signal correlation,
Runtime Compare, and deterministic alert explanations run locally.
Nick still uses the network for explicit product functions: Sparkle update
checks, an optional webhook configured in Settings, and links the user opens.
Exports remain local until the user chooses where to save or share them.

### Optional verdict learning

Settings → Data includes **Learn from my review decisions**, which is off by
default. When enabled, an authenticated false-positive decision can lower the
priority of a later exact match for the same signed app, review rule, and
bounded context. The finding remains visible. Hash, signature, YARA,
persistence, high-risk-path, unsigned, ad-hoc, interpreter, and command-tool
findings are never affected.

Use **What Nick learned** to see each local entry, why it exists, when it
expires, and how often it was confirmed. Entries can be reset individually,
reset together, or exported to a file you choose. They are stored locally in
Nick's root-owned incident store and are not uploaded.

## Email Guard

Email Guard requires NickExtension to be running and to have Full Disk Access.
It observes supported Apple Mail and Outlook attachment locations. A green
state means the extension is active and monitoring; it does not claim that
every mail provider or remote-only message has been scanned.

## Quarantine

Quarantined items are moved out of their original location and recorded in the
Quarantine view. Review the original path and detection before restoring an
item. Restoring a known malicious file can make it executable again.

Restore puts the file back at its original location with its original owner
and permissions, except special privilege bits. Nick refuses the restore if a
file already exists at that location or if a folder on the original path has
been replaced by a link. Move the existing item or recreate the folder, then
try again.

## Performance

The Performance view reports storage opportunities and reviewed cleanup
actions. Read the item description before deleting data. Nick avoids deleting
documents and does not treat cache size alone as a security problem.

## Runtime Compare

Runtime Compare is a local diagnostic for understanding a Mac before and after
a controlled change. It is useful when installing or removing security, VPN,
MDM, or network software, changing extension approvals, or restarting after a
migration.

### Capture a comparison

1. Open **Runtime Compare** in the Diagnostics section.
2. Choose **Start a comparison** and select the scenario that best describes
   the planned change.
3. Let Nick finish the baseline capture.
4. Make the intended change. If a restart is required, restart normally; Nick
   preserves the bounded baseline locally.
5. Return to the pending comparison and capture the follow-up.
6. Review important changes, changes to review, informational changes, and
   sensor-visibility warnings separately.

A finding is not automatically a threat. Listening ports and connections are
point-in-time observations, and a destination absent from one capture may still
be available later. Nick suppresses raw process churn across restarts and uses
stable owner identities where practical.

### Evidence quality

- **Observed** means the provider directly reported the state in a capture.
- **Inferred** means Nick compared two observations, such as a destination not
  being seen again.
- **Cannot confirm** means a permission or sensor was unavailable. Nick reports
  that limitation instead of treating missing data as a removal.

### Export a support bundle

Use the export control to preview sanitized Markdown or JSON before saving it.
Sanitization redacts identifying paths, hostnames, addresses, and local account
values. Export does not upload anything, and it does not modify the original
comparison stored on the Mac.

Runtime Compare supports comparisons from the same Mac only. It does not
certify compliance, remediate MDM state, change extension settings, block
network traffic, or send fleet telemetry.

## Uninstall

Use Settings → Uninstall Nick, or open Nick Uninstaller from `/Applications`,
for a complete removal. The uninstaller disables protection, removes generated
data and settings, and deletes Nick and itself. Finder can move Nick.app to the
Trash, but that removes only the app bundle; it does not clean up protection
components or generated data. Nick shows an informational notification when
this Finder-only removal starts.

After removal, macOS may retain a disabled Full Disk Access entry with no
executable behind it. That privacy-list row is maintained by macOS and can be
removed manually from System Settings if desired.
