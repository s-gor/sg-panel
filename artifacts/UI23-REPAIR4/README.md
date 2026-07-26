# SG-Panel UI23 Repair4

This directory preserves the cumulative Repair4 source artifact.

Current cumulative fixes include:

- visible XMUX controls for XHTTP Reality and XHTTP TLS;
- Standard and For Russia — reduced presets;
- manual XMUX JSON;
- explicit current-versus-pending XMUX state;
- repaired Xray Server validation and save gate;
- updater compatibility with Python ZIP extraction;
- Node.js 24-compatible GitHub Actions.

The source archive is verified by GitHub Actions for SHA-256, ZIP integrity and
byte-for-byte equality with the corresponding repository files.

Local result before publication: 165 tests passed and 38 Jinja templates parsed.
Real server acceptance remains required.
