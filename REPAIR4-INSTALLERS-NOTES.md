# Repair4 current updater and full installer

Current cumulative packages are built from UI23 Repair4 Xray Radio Fix 1:

- `SG-PANEL-FIX40-UI23-REPAIR4-XRAY-RADIO-FIX1.run` — in-place update through `install-or-upgrade.sh`;
- `SG-PANEL-FIX40-FULL-UI23-REPAIR4-XRAY-RADIO-FIX1.run` — clean installation through `install.sh`.

The updater is the normal choice for an already installed Controller or SG-Node. It preserves the database and current settings, creates a safety backup and uses rollback on failure.

Both packages pass `--verify-only` and contain a byte-for-byte identical source payload.
