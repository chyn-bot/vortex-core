-- ============================================================================
-- Migration 011: generic asset register & lifecycle (spec §3.9)
--
-- A parallel, finance/custody-oriented register that complements the
-- engineering hierarchy (§3.1–3.3): asset cards, movement/transfer, documents
-- and lifecycle events, for custody and audit.
--
-- SCOPE (per product decision): custody + lifecycle only. The depreciation /
-- book-value / account-journal surface of §3.9 is intentionally DEFERRED to the
-- core `vortex-accounting` fixed-assets module rather than reimplemented here.
-- ============================================================================

-- ── Asset category (tree) ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS eam_asset_category (
    id            UUID PRIMARY KEY,
    company_id    UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name          VARCHAR(128) NOT NULL,
    complete_name VARCHAR(512),
    parent_id     UUID REFERENCES eam_asset_category(id) ON DELETE SET NULL,
    code          VARCHAR(32),
    description   TEXT,
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_eam_asset_category_parent ON eam_asset_category(parent_id);

-- ── Asset location (tree) ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS eam_asset_location (
    id            UUID PRIMARY KEY,
    company_id    UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name          VARCHAR(128) NOT NULL,
    complete_name VARCHAR(512),
    parent_id     UUID REFERENCES eam_asset_location(id) ON DELETE SET NULL,
    code          VARCHAR(32),
    location_type VARCHAR(16) CHECK (location_type IS NULL OR location_type IN
                    ('site','building','floor','room','area','warehouse','other')),
    address       TEXT,
    responsible_id UUID REFERENCES users(id) ON DELETE SET NULL,
    gps_lat       NUMERIC(10,7),
    gps_lng       NUMERIC(10,7),
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_eam_asset_location_parent ON eam_asset_location(parent_id);

-- ── Asset (the register card) ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS eam_asset (
    id                 UUID PRIMARY KEY,
    company_id         UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    asset_code         VARCHAR(32),                       -- auto-generated, unique per company
    name               VARCHAR(256) NOT NULL,
    barcode            VARCHAR(64),
    serial_number      VARCHAR(128),
    description        TEXT,
    active             BOOLEAN NOT NULL DEFAULT TRUE,
    category_id        UUID REFERENCES eam_asset_category(id) ON DELETE SET NULL,
    asset_type         VARCHAR(16) NOT NULL DEFAULT 'tangible'
                         CHECK (asset_type IN ('tangible','intangible','leased')),
    location_id        UUID REFERENCES eam_asset_location(id) ON DELETE SET NULL,
    department         VARCHAR(128),                      -- plain text (no hr module)
    custodian_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    owner_id           UUID,                              -- soft partner ref
    vendor_id          UUID,                              -- soft partner ref
    state              VARCHAR(24) NOT NULL DEFAULT 'draft'
                         CHECK (state IN ('draft','pending_approval','active','in_storage',
                                          'in_maintenance','disposed','lost','cancelled')),
    criticality        VARCHAR(12) CHECK (criticality IS NULL OR
                                          criticality IN ('low','medium','high','critical')),
    acquisition_date   DATE,
    capitalization_date DATE,
    disposal_date      DATE,
    warranty_start_date DATE,
    warranty_end_date  DATE,
    purchase_order_ref VARCHAR(64),
    invoice_ref        VARCHAR(64),
    parent_id          UUID REFERENCES eam_asset(id) ON DELETE SET NULL,
    -- Division (§6.3): the register is cross-cutting; left unset (visible to
    -- both teams) unless a deployment classifies it. No auto-derivation.
    division           VARCHAR(16) CHECK (division IS NULL OR division IN ('transmission','distribution')),
    notes              TEXT,
    created_by         UUID,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_eam_asset_code UNIQUE (company_id, asset_code)
);
CREATE INDEX IF NOT EXISTS idx_eam_asset_category ON eam_asset(category_id);
CREATE INDEX IF NOT EXISTS idx_eam_asset_location ON eam_asset(location_id);
CREATE INDEX IF NOT EXISTS idx_eam_asset_state    ON eam_asset(state);

-- ── Asset movement (transfer workflow) ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS eam_asset_movement (
    id               UUID PRIMARY KEY,
    company_id       UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name             VARCHAR(32),
    asset_id         UUID NOT NULL REFERENCES eam_asset(id) ON DELETE CASCADE,
    movement_date    DATE NOT NULL DEFAULT CURRENT_DATE,
    reason           TEXT,
    from_location_id UUID REFERENCES eam_asset_location(id) ON DELETE SET NULL,
    to_location_id   UUID REFERENCES eam_asset_location(id) ON DELETE SET NULL,
    from_department  VARCHAR(128),
    to_department    VARCHAR(128),
    from_custodian_id UUID REFERENCES users(id) ON DELETE SET NULL,
    to_custodian_id  UUID REFERENCES users(id) ON DELETE SET NULL,
    state            VARCHAR(12) NOT NULL DEFAULT 'draft'
                       CHECK (state IN ('draft','confirmed','cancelled')),
    confirmed_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    confirmed_date   TIMESTAMPTZ,
    created_by       UUID,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_eam_asset_movement_asset ON eam_asset_movement(asset_id);

-- ── Asset document ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS eam_asset_document (
    id            UUID PRIMARY KEY,
    company_id    UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name          VARCHAR(256) NOT NULL,
    asset_id      UUID NOT NULL REFERENCES eam_asset(id) ON DELETE CASCADE,
    document_type VARCHAR(24) CHECK (document_type IS NULL OR document_type IN
                    ('purchase_order','invoice','warranty','manual','insurance',
                     'contract','certificate','photo','other')),
    file          BYTEA,
    file_name     VARCHAR(256),
    expiry_date   DATE,
    notes         TEXT,
    created_by    UUID,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_eam_asset_document_asset ON eam_asset_document(asset_id);

-- ── Lifecycle event (append-only audit trail per asset) ─────────────────────
CREATE TABLE IF NOT EXISTS eam_lifecycle_event (
    id             UUID PRIMARY KEY,
    company_id     UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    asset_id       UUID NOT NULL REFERENCES eam_asset(id) ON DELETE CASCADE,
    event_type     VARCHAR(24) NOT NULL
                     CHECK (event_type IN ('creation','approval','activation','transfer',
                                           'status_change','disposal','revaluation','update','other')),
    event_date     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description    TEXT,
    user_id        UUID,
    old_value      VARCHAR(256),
    new_value      VARCHAR(256),
    monetary_value NUMERIC(18,2),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_eam_lifecycle_event_asset ON eam_lifecycle_event(asset_id, event_date DESC);

-- Grant to the runtime role where present (mirrors migration 006).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON
            eam_asset_category, eam_asset_location, eam_asset,
            eam_asset_movement, eam_asset_document, eam_lifecycle_event TO vortex_runtime';
    END IF;
END$$;
