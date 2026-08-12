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

## Email Guard

Email Guard requires NickExtension to be running and to have Full Disk Access.
It observes supported Apple Mail and Outlook attachment locations. A green
state means the extension is active and monitoring; it does not claim that
every mail provider or remote-only message has been scanned.

## Quarantine

Quarantined items are moved out of their original location and recorded in the
Quarantine view. Review the original path and detection before restoring an
item. Restoring a known malicious file can make it executable again.

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

Use Nick Uninstaller from `/Applications`. Do not drag Nick to the Trash while
its system extensions or network filter are active. The uninstaller disables
protection, removes generated data and settings, and deletes Nick and itself.

After removal, macOS may retain a disabled Full Disk Access entry with no
executable behind it. That privacy-list row is maintained by macOS and can be
removed manually from System Settings if desired.
