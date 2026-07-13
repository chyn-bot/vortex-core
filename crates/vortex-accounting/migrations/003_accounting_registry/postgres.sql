-- SUPERSEDED — the accounting registry metadata is now derived from the plugin's
-- `#[derive(Model)]` structs (`Plugin::models()`) and synced into
-- ir_model / ir_model_field by `vortex_orm::registry_sync` on every
-- provisioning path (db migrate / create, module install, apps-list refresh).
--
-- This migration is retained as a tombstone so its recorded key stays stable
-- for databases that already applied it. It intentionally does nothing.
-- Previous hand-seeded INSERTs lived here (acc_move/acc_account).
SELECT 1;
