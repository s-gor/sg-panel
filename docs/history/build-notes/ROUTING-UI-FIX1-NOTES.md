# SG-Panel UI23 Repair4 — Routing UI Fix 1

Base: Updater Safety Fix 1.

Only the Routing page is changed:

- page heading changed from `Маршрутизация` to `Routing`;
- the two top status cards no longer use a heavy outline or left accent border;
- their corner radius follows the panel theme variable;
- small explanatory text on Routing is increased locally in the status facts, rules, validation/apply area, warning block, and current-rules list;
- a dedicated Routing-only stylesheet with a new cache key guarantees that the browser receives the correction.

Not changed:

- global page-heading sizes;
- other pages;
- Direct/WARP/Block behavior;
- Routing backend, Xray validation, database, SG-Node, or updater safety logic;
- GitHub publication.
