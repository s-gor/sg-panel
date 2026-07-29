# UI23 Repair4 CI Fix 1

This correction changes only GitHub Actions and the preserved Repair4 source artifact.
Application code, XMUX presets, database behavior, templates, installers, and runtime logic are unchanged.

Fixed:

- regenerated the Repair4 source ZIP after the final `.gitattributes` update;
- removed the false source-artifact mismatch on `.gitattributes`;
- upgraded `actions/checkout` to v6;
- upgraded `actions/setup-python` to v6;
- improved source-artifact comparison diagnostics;
- preserved the Repair4 source ZIP as a non-recursive repository snapshot that excludes `artifacts/`.
