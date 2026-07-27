# SG-Panel UI23 Repair4 · Remaining UI Fix 2

Base: Remaining UI Fix 1 / Cluster Empty Fix 1 / GeoFiles UI Fix 1 / Routing UI Fix 1 / Updater Safety Fix 1.

This cumulative local completion closes the four items that were only partially implemented:
- Outbounds system outputs now use user-facing Direct/Block titles; tags and protocols remain only in “Дополнительно”.
- DNS main page no longer exposes queryStrategy, +local schemes or raw technical server addresses; those remain in Expert DNS.
- Security audit never falls back to raw endpoint names; known actions are localized and unknown actions use a neutral panel label.
- XMUX ready presets and manual block no longer use framed card borders; ready presets remain above manual XMUX.

No runtime, database, routing, WARP, Xray, Node or updater logic was changed.
