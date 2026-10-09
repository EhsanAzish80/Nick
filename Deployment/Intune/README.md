# Unsupported experimental Intune profiles

> **Not supported in Nick 5.0.** These profiles are retained as development
> material only. They have not passed a managed-tenant deployment, upgrade, or
> rollback matrix and are not release assets. Do not distribute them as a
> supported Nick installation or management channel.

These profiles were generated for an earlier 4.1 experiment. Their presence in
the repository is not evidence that they remain correct for current builds.
Use them only when developing a future managed-tenant validation plan; do not
manually install them on a personal or production Mac.

## Historical 4.1 experiment (not a 5.0 deployment guide)

1. `Nick_System_Extensions.mobileconfig`
2. `Nick_Full_Disk_Access.mobileconfig`
3. `Nick_Network_Filter.mobileconfig`
4. `Nick_Managed_Configuration.mobileconfig`
5. Install the notarized Nick Enterprise Pilot 4.1 build 419 package.
6. Restart the pilot Mac if macOS or Intune reports that an extension approval
   is pending.

All four profiles are device-channel payloads. Assign them to a small pilot
device group before broader deployment.

## Expected validation

After Intune reports all profiles as installed and Nick is running, execute:

```sh
/usr/local/bin/nickctl status --json
```

The expected result is exit code `0`, managed configuration detected, and both
`endpoint-security` and `network-filter` reporting `available`, `enabled`, and
`responsive`.

The Network Filter profile deliberately starts build 419 in fail-open
observation mode. This pilot profile must not be
used as evidence that network blocking policy is enforced.

## Identity lock

- Apple Team ID: `UXGW5V3BY6`
- App: `com.ehsanazish.nick`
- Endpoint Security extension: `com.ehsanazish.nick.NickExtension`
- Network Filter extension: `com.ehsanazish.nick.NickNetFilter`

The PPPC and Network Filter requirements were derived from the notarized,
installed build 419 using `codesign -d -r-`. If Nick changes signing team or
bundle identifiers, regenerate the profiles instead of editing only the visible
identifier fields.

## Safety boundary

The files are unsigned XML configuration profiles so Intune can ingest them as
custom profiles. Review their full contents before upload. Do not accept
modified profiles returned by a third party without repeating syntax, schema,
identity, and designated-requirement validation.
