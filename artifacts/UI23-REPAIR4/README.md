# SG-Panel UI23 Repair4 source artifact

This directory preserves the accepted Repair4 source snapshot with visible XMUX presets.

The source ZIP intentionally excludes the repository `artifacts/` directory to avoid recursive archives. GitHub Actions verifies that every file stored in the ZIP exists in the repository and matches byte-for-byte.

CI Fix 1:

- source ZIP regenerated after the final `.gitattributes` update;
- `actions/checkout` upgraded to v6;
- `actions/setup-python` upgraded to v6;
- no SG-Panel application or XMUX runtime code changed.
