-- Vortex Intake — governed public web-forms (Phase 0).
--
-- A `web_form` publishes a chosen subset of a model's fields at a public URL.
-- A logged-out visitor submits it and a real record is written into the target
-- model — but ONLY the fields the form declares are writable (the allow-list is
-- the security seam; it closes mass-assignment), the tenant/owner are stamped
-- server-side, and the write is WORM-audited. `web_form_submission` is a light
-- ledger for triage/analytics; the real record lives in the target model table.
--
-- The target `model` is any `ir_model.name` — compiled or Blueprint (`x_`) — so
-- Intake pairs directly with Blueprints: design a model no-code, publish a
-- governed public form for it no-code.

CREATE TABLE IF NOT EXISTS web_form (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug         VARCHAR(64)  NOT NULL UNIQUE,          -- public URL segment (/i/<slug>)
    model        VARCHAR(128) NOT NULL,                 -- ir_model.name (the write target)
    title        VARCHAR(255) NOT NULL,
    description  TEXT,
    fields       JSONB NOT NULL DEFAULT '[]'::jsonb,    -- ordered allow-list: [{name,label,help,required}]
    settings     JSONB NOT NULL DEFAULT '{}'::jsonb,    -- {origins:[],success_msg,quarantine,notify_to,daily_cap}
    company_id   UUID REFERENCES companies(id),         -- tenant company stamped onto submissions
    active       BOOLEAN NOT NULL DEFAULT true,
    created_by   UUID REFERENCES users(id),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_web_form_active ON web_form (active);

CREATE TABLE IF NOT EXISTS web_form_submission (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    form_id     UUID NOT NULL REFERENCES web_form(id) ON DELETE CASCADE,
    record_id   UUID,                                    -- row created in the target model (NULL if quarantined/rejected)
    status      VARCHAR(16) NOT NULL DEFAULT 'accepted', -- accepted|quarantined|rejected
    source_ip   INET,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_wfs_status CHECK (status IN ('accepted', 'quarantined', 'rejected'))
);

CREATE INDEX IF NOT EXISTS idx_web_form_submission_form ON web_form_submission (form_id, created_at DESC);
