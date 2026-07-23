-- Rollback migration 164 (core): remove the generic record-API authz baseline.
-- With the baseline gone, generic-API requests fall to Cedar default-deny —
-- relevant only when API_POLICY_ENFORCED is set.
DELETE FROM policy_rules WHERE name = 'api_record_authz_baseline';
