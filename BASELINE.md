# Clean GitHub baseline

Repository baseline:

- core version: `v0.10.0-rc70`;
- build: `FIX40`;
- UI line: `Preview 9 · FIX40 · UI23`;
- Xray policy: `v26.6.27`;
- SG-Node Agent: `0.5.0`;
- SG-Node Worker: `0.7.0`.

This tree was prepared from the cumulative UI23 application plus the stable clean-install bootstrap. Rejected Routing UI25 and experimental UI24 installer wrappers are not included.

Removed from the repository root:

- historical `RELEASE-NOTES-*` files;
- generated `BUILD-*`, `TEST-RESULTS-*` and `STATIC-VALIDATION-*` reports;
- old package manifests, SHA-256 lists and audit files;
- temporary caches and compiled Python files.

Functional source, installers, documentation, assets and regression tests remain.
