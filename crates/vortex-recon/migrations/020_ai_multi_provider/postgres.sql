-- Reconciliation — multiple stored AI providers, one active at a time.
--
-- recon_ai_config already allowed many rows; the UI just treated it as a
-- singleton. This adds a friendly `name` so an admin can keep several named
-- provider profiles ("Claude Prod", "DeepSeek cheap", …), each with its own
-- key, and switch the active one. `active` remains the single selector the
-- extractor reads (WHERE active LIMIT 1).

ALTER TABLE recon_ai_config ADD COLUMN IF NOT EXISTS name VARCHAR(64);

-- Backfill a label for any pre-existing row.
UPDATE recon_ai_config
   SET name = INITCAP(provider)
 WHERE name IS NULL OR name = '';
