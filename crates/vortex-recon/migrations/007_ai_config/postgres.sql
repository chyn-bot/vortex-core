-- Reconciliation — per-tenant AI OCR provider configuration.
--
-- The tenant picks the provider (Claude/Anthropic, DeepSeek, OpenAI, or any
-- OpenAI-compatible endpoint), the model, and pastes their API key. The key is
-- stored AES-256-GCM encrypted (VORTEX_SECRET_KEY) — never in the clear, never
-- rendered back; only a last-4 hint is shown. Singleton per tenant (the app
-- reads the active row).

CREATE TABLE IF NOT EXISTS recon_ai_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider     VARCHAR(32)  NOT NULL DEFAULT 'anthropic', -- anthropic | openai | deepseek | custom
    model        VARCHAR(128) NOT NULL DEFAULT 'claude-opus-4-8',
    base_url     VARCHAR(255),          -- optional override (preset used when blank)
    api_key_enc  BYTEA,                 -- AES-256-GCM ciphertext (nonce-prefixed)
    api_key_hint VARCHAR(16),           -- last few chars, for "key set (…1234)" display
    active       BOOLEAN NOT NULL DEFAULT true,
    updated_by   UUID REFERENCES users(id),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
