# Hysteria2 Salamander FinalMask

Current implementation baseline: **Preview 9 · FIX40 · UI23**.

## Contract

Salamander belongs to a complete Hysteria2 Inbound, not to an individual client. The Hysteria2 client auth and the Salamander password are different secrets.

The database stores:

- `obfs_mode`: `none` or `salamander`;
- `obfs_password`;
- update time and actor.

Existing installations migrate to `none` without changing active profiles.

## Xray configuration

When enabled, SG-Panel adds a Salamander layer to `streamSettings.finalmask.udp` and preserves:

- `finalmask.quicParams`;
- other UDP layers;
- TCP layers;
- unrelated future FinalMask settings.

The managed layer sent to Xray has the form:

```json
{
  "type": "salamander",
  "settings": {
    "password": "SALAMANDER_PASSWORD"
  }
}
```

Internal ownership metadata is never written into the live Xray JSON.

## Safe apply

SG-Panel builds the full future candidate, runs `xray run -test`, applies atomically and verifies the service. On failure it restores the previous database state, Xray configuration, exports and runtime.

Minimum supported Xray version: **v26.3.27**.

## Client export

The same URI builder is used by copy, QR, download and subscriptions. With Salamander enabled the URI contains:

```text
obfs=salamander
obfs-password=...
```

Both parameters are absent when obfuscation is disabled.

## Security

The password is generated with a cryptographically secure random generator. It is not written to normal logs or diagnostic bundles. Backups preserve the exact value and Restore does not generate a replacement.

## Acceptance boundary

Static, migration, configuration, URI, backup and rollback behavior are implemented. A real external Hysteria2 + Salamander connection, password rotation and remote SG-Node application must still be confirmed on live servers before the feature is described as fully accepted.
