# SG-Panel UI23 Repair3 artifacts

This directory preserves the complete accepted Repair3 package alongside the
source tree in GitHub `main`.

Included:

- updater `.run`;
- full clean-install `.run`;
- updater/source ZIP;
- full/source ZIP;
- audit;
- SHA-256 manifest.

Status at publication time:

- GitHub Actions for the Repair3 source was green;
- 154 tests passed;
- real EC2 installation of these newly assembled `.run` files still requires
  acceptance testing;
- real Hysteria2 + Salamander client connectivity still requires acceptance
  testing.

The two `.run` files must pass `--verify-only`, and their embedded payloads must
match the preserved source ZIP byte-for-byte. GitHub Actions verifies this.
