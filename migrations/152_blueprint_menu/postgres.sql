-- Blueprints: per-blueprint "show in sidebar menu" opt-in.
--
-- A created Blueprint model is reachable from the Blueprints designer
-- ("Open records →"), but does not appear in the main navigation until an
-- admin explicitly adds it. This flag is the explicit opt-in that drives the
-- "Custom Apps" sidebar group: false by default (nothing shows unless asked),
-- flipped from the designer's "Add to menu" / "Remove from menu" action.
ALTER TABLE blueprint ADD COLUMN IF NOT EXISTS show_in_menu BOOLEAN NOT NULL DEFAULT false;
