# SG-Panel UI23 Repair 2

Current GitHub test-gate candidate.

Built from the last clean UI23 GitHub baseline, not from Repair1.

Included:

- accepted UI23 application and Salamander implementation;
- UI22 Node detail, UI21 Cluster and UI20 Cascade;
- the current cumulative CI suite (26 test files);
- two new regressions for legacy Hysteria2 records and the short-lived
  `obfs_password NOT NULL` schema.

Excluded:

- UI24 / UI24 FIX1 / UI24 FIX2;
- rejected UI25 Routing redesign;
- UI23 REBUILT1;
- Repair1 full historical test dump.

Repair2 corrects a real Repair1 code error: the legacy `obfs_password` storage
conversion had been inserted into `update_reality_inbounds()` and omitted from
`update_hysteria_inbounds()`.  That caused broad failures unrelated to the
accepted UI23 feature set.

Status:

- local current CI suite: 150 passed;
- GitHub Actions confirmation still required;
- no installer is accepted from this source until both Python jobs are green.
