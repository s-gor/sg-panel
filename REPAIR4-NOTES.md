# SG-Panel UI23 Repair 4

Base: GitHub-green UI23 Repair3.

XMUX is now visible directly in Xray Server and applies to both Always-On XHTTP channels.

Presets:

- Standard: maxConnections 2-4, cMaxReuseTimes 300-600, hMaxRequestTimes 1000-2000, hMaxReusableSecs 1200-2400, hKeepAlivePeriod 600.
- Russia reduced: maxConcurrency 0, maxConnections 6, cMaxReuseTimes 0, hMaxRequestTimes 600-900, hMaxReusableSecs 1800-3000, hKeepAlivePeriod 0.
- Manual Client Extra JSON remains available.

The validation rule now matches Xray-core: zero disables one controller, while positive maxConnections and positive maxConcurrency remain mutually exclusive.
