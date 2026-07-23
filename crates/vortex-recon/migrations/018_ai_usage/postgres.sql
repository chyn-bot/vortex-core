-- Reconciliation — AI token usage + extraction cost tracking.
--
-- Every extraction call records the provider-reported token counts and the
-- cost derived from an editable per-model rate card. Cost is stored on the
-- usage row (not recomputed on read) so historical figures stay stable even
-- after the rate card is edited. Surfaced on a superadmin-only page.

-- Editable rate card: cost per 1,000,000 tokens, per provider+model.
CREATE TABLE IF NOT EXISTS recon_ai_pricing (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider        VARCHAR(32)  NOT NULL,
    model           VARCHAR(128) NOT NULL,
    input_per_mtok  NUMERIC(12,4) NOT NULL DEFAULT 0,
    output_per_mtok NUMERIC(12,4) NOT NULL DEFAULT 0,
    currency        VARCHAR(8)   NOT NULL DEFAULT 'USD',
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (provider, model)
);

-- Per-call usage log. batch_id is a soft reference (no FK — a batch may be
-- deleted while its usage history is retained for cost reporting).
CREATE TABLE IF NOT EXISTS recon_ai_usage (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id      UUID,
    provider      VARCHAR(32)  NOT NULL,
    model         VARCHAR(128) NOT NULL,
    input_tokens  BIGINT NOT NULL DEFAULT 0,
    output_tokens BIGINT NOT NULL DEFAULT 0,
    cost          NUMERIC(14,6) NOT NULL DEFAULT 0,
    currency      VARCHAR(8) NOT NULL DEFAULT 'USD',
    created_by    UUID,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS recon_ai_usage_created_idx ON recon_ai_usage (created_at DESC);
CREATE INDEX IF NOT EXISTS recon_ai_usage_batch_idx   ON recon_ai_usage (batch_id);

-- Seed editable default rates (USD per 1M tokens; approximate public list
-- prices — a superadmin adjusts these to the tenant's negotiated rates).
INSERT INTO recon_ai_pricing (provider, model, input_per_mtok, output_per_mtok, currency) VALUES
    ('anthropic', 'claude-opus-4-8',           15.00, 75.00, 'USD'),
    ('anthropic', 'claude-sonnet-5',            3.00,  15.00, 'USD'),
    ('anthropic', 'claude-haiku-4-5-20251001',  0.80,  4.00,  'USD'),
    ('openai',    'gpt-4o',                      2.50,  10.00, 'USD'),
    ('deepseek',  'deepseek-chat',              0.27,  1.10,  'USD')
ON CONFLICT (provider, model) DO NOTHING;
