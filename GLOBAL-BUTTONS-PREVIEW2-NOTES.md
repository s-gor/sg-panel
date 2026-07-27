# Global Buttons Preview 2

Cumulative visual-only correction over Global Buttons Preview 1.

The first preview loaded last, but several historical `button.button.primary`
rules had equal or higher specificity and still painted primary actions with the
old darker `#41586f` material. This was visible on Outbounds: `Инструкция` and
`Создать из JSON` matched the reference while `Создать WARP` and `Добавить выход`
did not.

Preview 2 adds a final higher-specificity cascade layer. Every ordinary textual
action button now uses exactly one material regardless of semantic class:

- dark: `#58738d`, border `#7892aa`, white 800-weight label;
- light: the same active Luxury Jade gradient, champagne border and white label;
- primary, secondary, ghost, warning, danger and toggle no longer override it;
- disabled state differs only by opacity;
- icon-only controls, sidebar navigation and status pills remain unchanged.

No backend, database, Routing, Xray, GeoFiles, WARP, XMUX or Salamander logic was changed.
