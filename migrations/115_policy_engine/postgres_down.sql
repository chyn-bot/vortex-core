-- Rollback migration 115: drop the policy engine tables.
DROP TRIGGER IF EXISTS trg_policy_rules_updated_at ON policy_rules;
DROP INDEX IF EXISTS idx_policy_rules_active;
DROP INDEX IF EXISTS idx_policy_rules_company;
DROP TABLE IF EXISTS policy_rules;
