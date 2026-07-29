# UI23 Repair 2

Repair1 restored 122 chronological test files into one pytest run. Those files
are not one coherent current contract: many intentionally assert older RC/UI
layouts and older service behaviour. Running them together produced 260
failures and four setup errors.

Repair2 returns CI to the maintained cumulative suite from the clean UI23
baseline and adds focused regression coverage for the actual Salamander
compatibility defects.

Production fixes:

1. `update_reality_inbounds()` no longer reads Hysteria2 obfuscation fields.
2. `update_hysteria_inbounds()` writes the disabled password in a form accepted
   by both current nullable schemas and the short-lived legacy NOT NULL schema.
3. `update_hysteria_obfuscation()` uses the same storage compatibility rule.
4. Legacy saved-link/inbound mappings without `obfs_mode` or `obfs_password`
   are treated as `none` / not configured, preventing KeyError.

No UI, Routing, Cluster, Cascade, Xray bootstrap or installer flow was changed.
