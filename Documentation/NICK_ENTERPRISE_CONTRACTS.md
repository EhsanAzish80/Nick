# Nick Enterprise Contracts

This document freezes the initial machine-readable contract for the Enterprise
Pilot. Implementations may add optional fields only through a new schema
version; published meanings, error codes, and exit codes are never reassigned.

## Commands

The planned `nickctl` interface has three commands:

```text
nickctl status --json
nickctl diagnostics --output <absolute-directory>
nickctl compare --baseline <snapshot> --output <absolute-path>
```

The pilot must not perform remediation, unload another vendor's extension, or
upload an artifact. Commands write only to an explicitly configured local path.

`status --json` is implemented in the signed installer. It runs Nick's signed
executable in a prohibited, headless mode, queries the same live providers as
the Organization view, writes one versioned JSON envelope to standard output,
and exits. It does not install, enable, disable, or remediate a provider.

A non-zero status result may still include a partial health report in `payload`
so administrators retain the evidence Nick could collect. Unavailable or
unconfigured providers exit `22`, degraded evidence exits `21`, missing proof
exits `20`, invalid forced configuration exits `10`, and fully verified
providers exit `0`.

## Managed configuration and runtime proof

Nick reads managed policy from the `enterpriseManagedConfiguration` dictionary
in its application preference domain. The dictionary is accepted only when
macOS reports that exact preference as forced by device management. A local
`defaults write`, Settings change, or ordinary `UserDefaults` value is ignored
and cannot masquerade as organization policy.

Runtime status is evidence-backed:

- Endpoint Security is available only after its XPC service answers a live
  status request.
- Network Filter is available only when the enabled provider publishes a
  current, valid health record.
- Missing evidence is reported as `cannotVerify`; it is not translated into a
  claim that the provider is installed, removed, enabled, or disabled.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Operation completed successfully |
| 2 | Invalid command or arguments |
| 10 | Managed configuration is invalid |
| 20 | Operation completed with a visibility limitation |
| 21 | A component is responding in a degraded state |
| 22 | A required component is unavailable |
| 30 | The requested operation failed |
| 31 | Atomic output creation failed |
| 40 | Input uses an unsupported schema version |

Exit `20` is not equivalent to failure or component removal. It means Nick
cannot prove the requested state with available evidence.

## Stable error identifiers

| Identifier | Meaning |
| --- | --- |
| `NICK-CLI-001` | Invalid command or arguments |
| `NICK-CONFIG-001` | Invalid managed configuration |
| `NICK-SCHEMA-001` | Unsupported schema version |
| `NICK-VISIBILITY-001` | Required evidence is not observable |
| `NICK-ENDPOINT-001` | Endpoint Security provider is not responsive |
| `NICK-NETWORK-001` | Network Filter provider is not responsive |
| `NICK-NETWORK-002` | Another network filter or incompatible policy conflicts |
| `NICK-DIAGNOSTIC-001` | Diagnostic capture failed |
| `NICK-OUTPUT-001` | Output could not be written atomically |

User-facing messages may improve without changing the identifier. Logs and
automation must branch on the identifier and exit code, never English text.

## Schemas

Draft 2020-12 JSON Schemas are stored in [`Schemas`](Schemas/):

- `nick-managed-configuration-v1.schema.json`
- `nick-health-report-v1.schema.json`
- `nick-cli-envelope-v1.schema.json`
- `nick-diagnostic-manifest-v1.schema.json`
- `nick-baseline-manifest-v1.schema.json`

Unknown schema versions are rejected. Decoders must not silently discard an
unknown version and continue with local defaults.

## Baseline terminology

The baseline contract contains signed metadata and runtime-verifiable
assertions. A future evaluator may return only:

- `matches`
- `contradicts`
- `cannotVerify`

These are evidence statements, not formal compliance results.
