-- Migration: SESB EAM foundation (vortex-sesb-eam plugin)
--
-- Phase 1 — reference/master data + the location hierarchy
-- (Region → Zon → Kawasan → Site → Substation → Bay).
--
-- Field-level parity with SESB_EAM_BUILD_SPECIFICATION §3.1, §3.11.
-- Enums are realised as VARCHAR + CHECK (the typed-enum contract from
-- §2.3) so the allowed value sets are enforced in the database.
-- Computed/read-only fields (counts, age_years, end_of_life_date,
-- mnec_type_code, aging_matrix, …) are NOT stored — they are derived on
-- read per §2.3 ("computed fields are functions, not columns").
--
-- Reuses core: companies, users, countries. Owns the eam_* namespace.

-- ============================================================================
-- REFERENCE / MASTER DATA (§3.11)
-- ============================================================================

-- Voltage levels --------------------------------------------------------------
CREATE TABLE IF NOT EXISTS eam_voltage_level (
    id           UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name         VARCHAR(120) NOT NULL,
    code         VARCHAR(32)  NOT NULL,
    voltage_kv   NUMERIC(12,4),
    voltage_type VARCHAR(4)   NOT NULL DEFAULT 'ac',
    description  TEXT,
    active       BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id   UUID         REFERENCES companies(id),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_vlevel_type CHECK (voltage_type IN ('ac', 'dc')),
    CONSTRAINT uq_eam_vlevel_code  UNIQUE (company_id, code)
);
DROP TRIGGER IF EXISTS trg_eam_vlevel_updated_at ON eam_voltage_level;
CREATE TRIGGER trg_eam_vlevel_updated_at BEFORE UPDATE ON eam_voltage_level
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Manufacturers ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS eam_manufacturer (
    id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(160) NOT NULL,
    code        VARCHAR(32)  NOT NULL,
    country_id  UUID         REFERENCES countries(id),
    website     VARCHAR(200),
    phone       VARCHAR(60),
    email       VARCHAR(160),
    notes       TEXT,
    active      BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id  UUID         REFERENCES companies(id),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_eam_manufacturer_code UNIQUE (company_id, code)
);
DROP TRIGGER IF EXISTS trg_eam_manufacturer_updated_at ON eam_manufacturer;
CREATE TRIGGER trg_eam_manufacturer_updated_at BEFORE UPDATE ON eam_manufacturer
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Asset classification (BRD §7.5/§7.6) ----------------------------------------
CREATE TABLE IF NOT EXISTS eam_asset_class (
    id                       UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                     VARCHAR(160) NOT NULL,
    code                     VARCHAR(32)  NOT NULL,
    sequence                 INTEGER      NOT NULL DEFAULT 0,
    class_type               VARCHAR(16)  NOT NULL DEFAULT 'electrical',
    class_group              VARCHAR(32),
    parent_id                UUID         REFERENCES eam_asset_class(id) ON DELETE SET NULL,
    parent_path              VARCHAR(255),
    description              TEXT,
    scope_notes              TEXT,
    remarks                  TEXT,
    default_maintenance_tier VARCHAR(8),
    tier1_frequency_months   INTEGER,
    tier2_frequency_months   INTEGER,
    -- FK to eam_checklist_template added in a later phase migration.
    default_checklist_template_id UUID,
    default_duration_hours   NUMERIC(10,2),
    active                   BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id               UUID         REFERENCES companies(id),
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_aclass_type CHECK (class_type IN ('electrical', 'non_electrical')),
    CONSTRAINT chk_eam_aclass_tier CHECK (default_maintenance_tier IS NULL OR default_maintenance_tier IN ('tier1','tier2','tier3')),
    CONSTRAINT uq_eam_aclass_code UNIQUE (company_id, code)
);
CREATE INDEX IF NOT EXISTS idx_eam_aclass_parent ON eam_asset_class (parent_id);
DROP TRIGGER IF EXISTS trg_eam_aclass_updated_at ON eam_asset_class;
CREATE TRIGGER trg_eam_aclass_updated_at BEFORE UPDATE ON eam_asset_class
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Asset-type acronym registry (drives MNEC asset_id + attribute schema) --------
CREATE TABLE IF NOT EXISTS eam_asset_type (
    id                      UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    acronym                 VARCHAR(16)  NOT NULL,
    name                    VARCHAR(160) NOT NULL,
    description             TEXT,
    category                VARCHAR(32)  NOT NULL DEFAULT 'primary_equipment',
    default_hierarchy_level INTEGER,
    attribute_schema        VARCHAR(24)  NOT NULL DEFAULT 'generic',
    active                  BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id              UUID         REFERENCES companies(id),
    created_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_atype_level CHECK (default_hierarchy_level IS NULL OR default_hierarchy_level BETWEEN 1 AND 4),
    CONSTRAINT chk_eam_atype_schema CHECK (attribute_schema IN ('transformer','phase_primary','relay_control','tower_hardware','ugc_accessory','generic')),
    CONSTRAINT uq_eam_atype_acronym UNIQUE (company_id, acronym)
);
DROP TRIGGER IF EXISTS trg_eam_atype_updated_at ON eam_asset_type;
CREATE TRIGGER trg_eam_atype_updated_at BEFORE UPDATE ON eam_asset_type
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- LOCATION HIERARCHY (§3.1)
-- ============================================================================

-- Region / Division -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS eam_region (
    id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(160) NOT NULL,
    code        VARCHAR(32)  NOT NULL,
    sequence    INTEGER      NOT NULL DEFAULT 0,
    division    VARCHAR(16)  NOT NULL DEFAULT 'distribution',
    description TEXT,
    active      BOOLEAN      NOT NULL DEFAULT TRUE,
    manager_id  UUID         REFERENCES users(id),
    company_id  UUID         REFERENCES companies(id),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_region_div CHECK (division IN ('transmission','distribution')),
    CONSTRAINT uq_eam_region_code UNIQUE (company_id, code)
);
DROP TRIGGER IF EXISTS trg_eam_region_updated_at ON eam_region;
CREATE TRIGGER trg_eam_region_updated_at BEFORE UPDATE ON eam_region
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Zon (operational zone) ------------------------------------------------------
CREATE TABLE IF NOT EXISTS eam_zon (
    id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(160) NOT NULL,
    code        VARCHAR(32)  NOT NULL,
    sequence    INTEGER      NOT NULL DEFAULT 0,
    region_id   UUID         NOT NULL REFERENCES eam_region(id) ON DELETE CASCADE,
    manager_id  UUID         REFERENCES users(id),
    description TEXT,
    active      BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id  UUID         REFERENCES companies(id),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_eam_zon_code UNIQUE (company_id, code)
);
CREATE INDEX IF NOT EXISTS idx_eam_zon_region ON eam_zon (region_id);
DROP TRIGGER IF EXISTS trg_eam_zon_updated_at ON eam_zon;
CREATE TRIGGER trg_eam_zon_updated_at BEFORE UPDATE ON eam_zon
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Kawasan (district / area) ---------------------------------------------------
CREATE TABLE IF NOT EXISTS eam_kawasan (
    id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        VARCHAR(160) NOT NULL,
    code        VARCHAR(32)  NOT NULL,
    sequence    INTEGER      NOT NULL DEFAULT 0,
    zon_id      UUID         NOT NULL REFERENCES eam_zon(id) ON DELETE CASCADE,
    region_id   UUID         REFERENCES eam_region(id) ON DELETE SET NULL,
    manager_id  UUID         REFERENCES users(id),
    description TEXT,
    active      BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id  UUID         REFERENCES companies(id),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_eam_kawasan_code UNIQUE (company_id, code)
);
CREATE INDEX IF NOT EXISTS idx_eam_kawasan_zon    ON eam_kawasan (zon_id);
CREATE INDEX IF NOT EXISTS idx_eam_kawasan_region ON eam_kawasan (region_id);
DROP TRIGGER IF EXISTS trg_eam_kawasan_updated_at ON eam_kawasan;
CREATE TRIGGER trg_eam_kawasan_updated_at BEFORE UPDATE ON eam_kawasan
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Site location ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS eam_site (
    id                   UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                 VARCHAR(200)  NOT NULL,
    code                 VARCHAR(32)   NOT NULL,
    region_id            UUID          NOT NULL REFERENCES eam_region(id) ON DELETE CASCADE,
    kawasan_id           UUID          REFERENCES eam_kawasan(id) ON DELETE SET NULL,
    zon_id               UUID          REFERENCES eam_zon(id) ON DELETE SET NULL,
    site_type            VARCHAR(16)   NOT NULL DEFAULT 'pe',
    address              TEXT,
    gps_latitude         NUMERIC(12,7),
    gps_longitude        NUMERIC(12,7),
    state                VARCHAR(20)   NOT NULL DEFAULT 'operational',
    commissioning_date   DATE,
    decommissioning_date DATE,
    notes                TEXT,
    active               BOOLEAN       NOT NULL DEFAULT TRUE,
    company_id           UUID          REFERENCES companies(id),
    created_at           TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_site_type  CHECK (site_type IN ('pmu','ppu','ssu_33kv','ssu_11kv','pp','pe','ss','isolation','other')),
    CONSTRAINT chk_eam_site_state CHECK (state IN ('planning','construction','operational','decommissioned')),
    CONSTRAINT uq_eam_site_code   UNIQUE (company_id, code)
);
CREATE INDEX IF NOT EXISTS idx_eam_site_region  ON eam_site (region_id);
CREATE INDEX IF NOT EXISTS idx_eam_site_kawasan ON eam_site (kawasan_id);
DROP TRIGGER IF EXISTS trg_eam_site_updated_at ON eam_site;
CREATE TRIGGER trg_eam_site_updated_at BEFORE UPDATE ON eam_site
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Substation (Pencawang) — carries the asset-verification mixin ---------------
CREATE TABLE IF NOT EXISTS eam_substation (
    id                    UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- AssetVerificationMixin (§3.12)
    verification_state    VARCHAR(12)   NOT NULL DEFAULT 'draft',
    submitted_by_id       UUID          REFERENCES users(id),
    submitted_date        TIMESTAMPTZ,
    verified_by_id        UUID          REFERENCES users(id),
    verified_date         TIMESTAMPTZ,
    approved_by_id        UUID          REFERENCES users(id),
    approved_date         TIMESTAMPTZ,
    rejected_by_id        UUID          REFERENCES users(id),
    rejected_date         TIMESTAMPTZ,
    rejection_reason      TEXT,
    verification_revision INTEGER       NOT NULL DEFAULT 0,
    -- identity
    name                  VARCHAR(200)  NOT NULL,
    code                  VARCHAR(32)   NOT NULL,
    asset_id              VARCHAR(120),
    asset_type_id         UUID          REFERENCES eam_asset_type(id),
    primary_voltage_kv    NUMERIC(12,4),
    site_id               UUID          NOT NULL REFERENCES eam_site(id) ON DELETE CASCADE,
    substation_type       VARCHAR(16),
    busbar_configuration  VARCHAR(16),
    substation_class      VARCHAR(16),
    source_from           VARCHAR(120),
    feeder                VARCHAR(120),
    customers_served      INTEGER       NOT NULL DEFAULT 0,
    substation_category   VARCHAR(60),
    automation_type       VARCHAR(60),
    site_size             VARCHAR(60),
    gps_latitude          VARCHAR(40),
    gps_longitude         VARCHAR(40),
    ownership             VARCHAR(12)   NOT NULL DEFAULT 'sesb',
    commissioning_date    DATE,
    design_life_years     INTEGER       NOT NULL DEFAULT 40,
    state                 VARCHAR(20)   NOT NULL DEFAULT 'operational',
    notes                 TEXT,
    active                BOOLEAN       NOT NULL DEFAULT TRUE,
    company_id            UUID          REFERENCES companies(id),
    created_by            UUID          REFERENCES users(id),
    updated_by            UUID          REFERENCES users(id),
    created_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_substation_vstate CHECK (verification_state IN ('draft','submitted','verified','approved','rejected')),
    CONSTRAINT chk_eam_substation_type   CHECK (substation_type IS NULL OR substation_type IN ('indoor','outdoor','compact','underground')),
    CONSTRAINT chk_eam_substation_busbar CHECK (busbar_configuration IS NULL OR busbar_configuration IN ('single','double','ring','breaker_half')),
    CONSTRAINT chk_eam_substation_class  CHECK (substation_class IS NULL OR substation_class IN ('pmu','ppu','ssu','pp','pe','isolation')),
    CONSTRAINT chk_eam_substation_owner  CHECK (ownership IN ('sesb','ipp','customer','shared')),
    CONSTRAINT chk_eam_substation_state  CHECK (state IN ('planning','construction','operational','maintenance','decommissioned')),
    CONSTRAINT uq_eam_substation_code    UNIQUE (company_id, code),
    CONSTRAINT uq_eam_substation_asset_id UNIQUE (company_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_eam_substation_site  ON eam_substation (site_id);
CREATE INDEX IF NOT EXISTS idx_eam_substation_vstate ON eam_substation (verification_state);
DROP TRIGGER IF EXISTS trg_eam_substation_updated_at ON eam_substation;
CREATE TRIGGER trg_eam_substation_updated_at BEFORE UPDATE ON eam_substation
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Bay / Circuit — carries the asset-verification mixin ------------------------
CREATE TABLE IF NOT EXISTS eam_bay (
    id                    UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- AssetVerificationMixin (§3.12)
    verification_state    VARCHAR(12)   NOT NULL DEFAULT 'draft',
    submitted_by_id       UUID          REFERENCES users(id),
    submitted_date        TIMESTAMPTZ,
    verified_by_id        UUID          REFERENCES users(id),
    verified_date         TIMESTAMPTZ,
    approved_by_id        UUID          REFERENCES users(id),
    approved_date         TIMESTAMPTZ,
    rejected_by_id        UUID          REFERENCES users(id),
    rejected_date         TIMESTAMPTZ,
    rejection_reason      TEXT,
    verification_revision INTEGER       NOT NULL DEFAULT 0,
    -- identity
    name                  VARCHAR(200)  NOT NULL,
    code                  VARCHAR(32)   NOT NULL,
    bay_number            INTEGER,
    asset_id              VARCHAR(120),
    substation_id         UUID          NOT NULL REFERENCES eam_substation(id) ON DELETE CASCADE,
    bay_type              VARCHAR(20)   NOT NULL DEFAULT 'outgoing',
    voltage_level_id      UUID          REFERENCES eam_voltage_level(id),
    busbar_configuration  VARCHAR(16),
    rated_current_a       NUMERIC(12,2),
    rated_fault_current_ka NUMERIC(12,2),
    feeder_name           VARCHAR(120),
    feeder_number         VARCHAR(60),
    destination           VARCHAR(200),
    scada_point_group     VARCHAR(120),
    sld_reference         VARCHAR(120),
    state                 VARCHAR(20)   NOT NULL DEFAULT 'in_service',
    notes                 TEXT,
    active                BOOLEAN       NOT NULL DEFAULT TRUE,
    company_id            UUID          REFERENCES companies(id),
    created_by            UUID          REFERENCES users(id),
    updated_by            UUID          REFERENCES users(id),
    created_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_bay_vstate CHECK (verification_state IN ('draft','submitted','verified','approved','rejected')),
    CONSTRAINT chk_eam_bay_type   CHECK (bay_type IN ('incoming','outgoing','bus_coupler','bus_section','transformer','capacitor','metering','auxiliary','other')),
    CONSTRAINT chk_eam_bay_busbar CHECK (busbar_configuration IS NULL OR busbar_configuration IN ('single','double','ring','breaker_half')),
    CONSTRAINT chk_eam_bay_state  CHECK (state IN ('available','in_service','out_of_service','under_maintenance','reserved')),
    CONSTRAINT uq_eam_bay_code    UNIQUE (company_id, code)
);
CREATE INDEX IF NOT EXISTS idx_eam_bay_substation ON eam_bay (substation_id);
CREATE INDEX IF NOT EXISTS idx_eam_bay_vstate     ON eam_bay (verification_state);
DROP TRIGGER IF EXISTS trg_eam_bay_updated_at ON eam_bay;
CREATE TRIGGER trg_eam_bay_updated_at BEFORE UPDATE ON eam_bay
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Voltage-level many-to-many links (site / substation voltage_level_ids) -------
CREATE TABLE IF NOT EXISTS eam_site_voltage_level (
    site_id          UUID NOT NULL REFERENCES eam_site(id) ON DELETE CASCADE,
    voltage_level_id UUID NOT NULL REFERENCES eam_voltage_level(id) ON DELETE CASCADE,
    PRIMARY KEY (site_id, voltage_level_id)
);
CREATE TABLE IF NOT EXISTS eam_substation_voltage_level (
    substation_id    UUID NOT NULL REFERENCES eam_substation(id) ON DELETE CASCADE,
    voltage_level_id UUID NOT NULL REFERENCES eam_voltage_level(id) ON DELETE CASCADE,
    PRIMARY KEY (substation_id, voltage_level_id)
);

-- ============================================================================
-- Runtime role grants
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON
            eam_voltage_level, eam_manufacturer, eam_asset_class, eam_asset_type,
            eam_region, eam_zon, eam_kawasan, eam_site, eam_substation, eam_bay,
            eam_site_voltage_level, eam_substation_voltage_level TO vortex_runtime';
    END IF;
END$$;

COMMENT ON TABLE eam_substation IS
    'SESB substation (Pencawang). Level-1 root of the MNEC asset hierarchy; carries the DAMS asset-verification workflow (draft→submitted→verified→approved).';
COMMENT ON TABLE eam_bay IS
    'Substation bay / circuit. Level-2 of the MNEC hierarchy; equipment hangs off a bay.';
