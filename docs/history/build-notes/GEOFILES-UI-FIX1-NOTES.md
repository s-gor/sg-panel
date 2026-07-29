# SG-Panel UI23 Repair4 — GeoFiles UI Fix 1

Base: Routing UI Fix 1 / Updater Safety Fix 1.

Only the installed linked-pair card on the standalone GeoFiles page is changed:

- `Текущий источник` and `Последняя проверка` form one balanced left column;
- `geoip.dat` and `geosite.dat` remain equal full-height file cards;
- internal cards no longer touch or intersect the outer card border;
- the outer card owns the only outer corner radius;
- the category disclosure is integrated as the card footer with one thin separator and no nested heavy outline;
- responsive layouts remain two columns and then one column on narrower screens.

Not changed:

- GeoFiles content, source selection, validation, staging, apply, rollback or Routing/Xray logic;
- global typography or page-heading sizes;
- other pages;
- GitHub or SG-Node.
