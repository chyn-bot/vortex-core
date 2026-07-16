-- Roles: tie a role to the plugin that owns it, so an uninstalled module's
-- roles neither grant access nor appear as assignable.
--
-- `vortex db migrate` provisions the schema of EVERY compiled-in plugin
-- (run_plugin_migrations), so a plugin's role-seeding migration runs even in a
-- tenant that never "installs" the module — leaving orphaned, assignable roles
-- (e.g. the six `EAM %` roles in a plain accounting tenant). `owning_module`
-- lets the auth path and the role pickers scope roles to installed modules:
-- a NULL owner means a core/global role (always active); a set owner means the
-- role is inert + hidden whenever that module is not installed, and reactivates
-- automatically if it ever is. Non-destructive: no grants are deleted.
ALTER TABLE roles ADD COLUMN IF NOT EXISTS owning_module VARCHAR;

-- Backfill the only plugin that currently seeds named roles (SESB EAM). Its
-- roles are identifiable by name prefix and by their `sesb_eam.*` permissions.
UPDATE roles
   SET owning_module = 'sesb_eam'
 WHERE owning_module IS NULL
   AND (name LIKE 'EAM %' OR permissions::text ILIKE '%sesb_eam%');
