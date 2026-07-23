-- Reconciliation — distinguish batch vs on-demand extraction cost.
--
-- The Anthropic Message Batches API bills ~50% of the synchronous price. Cost
-- is frozen per usage row, so we tag each row's mode and store the already
-- discounted cost for batch rows. Existing rows predate batching → 'ondemand'.

ALTER TABLE recon_ai_usage
    ADD COLUMN IF NOT EXISTS mode VARCHAR(16) NOT NULL DEFAULT 'ondemand'; -- ondemand | batch
