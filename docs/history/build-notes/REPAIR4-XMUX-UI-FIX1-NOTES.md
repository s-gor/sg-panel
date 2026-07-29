# UI23 Repair4 XMUX UI Fix 1

Confirmed defects fixed:

1. The Xray Server validation gate inserted the visible validation button and
   then raised a DOMException while trying to insert its status element. As a
   result, the validation click handler was never attached and both validation
   and save appeared non-functional.
2. The XMUX selector duplicated one dropdown and two read-only description
   cards, so it was unclear which element changed the profile.
3. The page did not distinguish the profile already stored in the database from
   a new unsaved selection.

Changes:

- robust validation-gate insertion for nested custom action layouts;
- XMUX presets are now three real radio-card controls;
- explicit `Сейчас применяется` block loaded from the database;
- `Сейчас активен` badge on the stored profile;
- `Выбран` badge and pending explanation for an unsaved profile;
- manual JSON appears only when the manual profile is selected;
- validation is still mandatory before save and apply.

No protocol values, XMUX presets, Xray generation, Salamander, Routing, Cluster,
Cascade, database migration, or installer architecture were changed.
