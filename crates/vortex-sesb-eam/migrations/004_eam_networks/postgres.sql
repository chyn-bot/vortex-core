-- Migration: SESB EAM transmission / distribution / UGC networks
--
-- Phase 3 — the line/tower/span/gantry/UGC asset records (§3.4–3.5) that
-- carry network-side equipment. TransmissionTower carries the
-- WayleaveMixin (§3.12). After the tables exist, the equipment
-- network-parent columns from Phase 2 are wired with FKs.

-- ============================================================================
-- Distribution network (§3.4)
-- ============================================================================
CREATE TABLE IF NOT EXISTS eam_distribution_line (
    id                   UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                 VARCHAR(200) NOT NULL,
    code                 VARCHAR(32),
    region_id            UUID         NOT NULL REFERENCES eam_region(id) ON DELETE CASCADE,
    site_id              UUID         REFERENCES eam_site(id) ON DELETE SET NULL,
    bay_id               UUID         REFERENCES eam_bay(id) ON DELETE SET NULL,
    line_type            VARCHAR(12)  NOT NULL DEFAULT 'overhead',
    voltage_level_id     UUID         REFERENCES eam_voltage_level(id),
    route_length_km      NUMERIC(12,4),
    number_of_circuits   INTEGER,
    conductor_type       VARCHAR(12),
    conductor_size_mm2   NUMERIC(12,2),
    number_of_poles      INTEGER,
    pole_material        VARCHAR(12),
    cable_type           VARCHAR(8),
    cable_size_mm2       NUMERIC(12,2),
    laying_method        VARCHAR(16),
    number_of_joints     INTEGER,
    number_of_terminations INTEGER,
    cable_condition      VARCHAR(12),
    last_pi_dar_test_date DATE,
    last_pi_value        NUMERIC(10,4),
    last_dar_value       NUMERIC(10,4),
    next_monitoring_date DATE,
    risk_area            VARCHAR(16),
    state                VARCHAR(16)  NOT NULL DEFAULT 'operational',
    commissioning_date   DATE,
    notes                TEXT,
    active               BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id           UUID         REFERENCES companies(id),
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_dline_type CHECK (line_type IN ('overhead','underground','mixed')),
    CONSTRAINT chk_eam_dline_cond CHECK (conductor_type IS NULL OR conductor_type IN ('aac','aaac','acsr','abc','covered')),
    CONSTRAINT chk_eam_dline_pole CHECK (pole_material IS NULL OR pole_material IN ('wood','concrete','steel','composite')),
    CONSTRAINT chk_eam_dline_cable CHECK (cable_type IS NULL OR cable_type IN ('xlpe','pilc','epr')),
    CONSTRAINT chk_eam_dline_lay CHECK (laying_method IS NULL OR laying_method IN ('direct_buried','duct','trough','tunnel')),
    CONSTRAINT chk_eam_dline_cablecond CHECK (cable_condition IS NULL OR cable_condition IN ('good','medium','poor','very_poor')),
    CONSTRAINT chk_eam_dline_risk CHECK (risk_area IS NULL OR risk_area IN ('normal','high_excavation','vip','flood_prone','coastal')),
    CONSTRAINT chk_eam_dline_state CHECK (state IN ('planning','construction','operational','out_of_service','decommissioned')),
    CONSTRAINT uq_eam_dline_code UNIQUE (company_id, code)
);
CREATE INDEX IF NOT EXISTS idx_eam_dline_region ON eam_distribution_line (region_id);
DROP TRIGGER IF EXISTS trg_eam_dline_updated_at ON eam_distribution_line;
CREATE TRIGGER trg_eam_dline_updated_at BEFORE UPDATE ON eam_distribution_line FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- Transmission network (§3.5)
-- ============================================================================
CREATE TABLE IF NOT EXISTS eam_transmission_line (
    id                   UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                 VARCHAR(200) NOT NULL,
    code                 VARCHAR(32),
    asset_id             VARCHAR(120),
    asset_type_id        UUID         REFERENCES eam_asset_type(id),
    hierarchy_level      INTEGER,
    region_id            UUID         NOT NULL REFERENCES eam_region(id) ON DELETE CASCADE,
    voltage_level_id     UUID         NOT NULL REFERENCES eam_voltage_level(id),
    from_substation_id   UUID         REFERENCES eam_substation(id) ON DELETE SET NULL,
    to_substation_id     UUID         REFERENCES eam_substation(id) ON DELETE SET NULL,
    line_length_km       NUMERIC(12,4),
    conductor_type       VARCHAR(8),
    conductor_size_mm2   NUMERIC(12,2),
    number_of_circuits   INTEGER,
    earth_wire_type      VARCHAR(60),
    rated_current_a      NUMERIC(12,2),
    max_sag_m            NUMERIC(10,2),
    state                VARCHAR(16)  NOT NULL DEFAULT 'operational',
    commissioning_date   DATE,
    design_life_years    INTEGER,
    ownership            VARCHAR(12)  NOT NULL DEFAULT 'sesb',
    notes                TEXT,
    active               BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id           UUID         REFERENCES companies(id),
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_tline_cond CHECK (conductor_type IS NULL OR conductor_type IN ('acsr','acar','aaac','aac','accc','htls')),
    CONSTRAINT chk_eam_tline_state CHECK (state IN ('planning','construction','operational','maintenance','decommissioned')),
    CONSTRAINT chk_eam_tline_owner CHECK (ownership IN ('sesb','ipp','shared')),
    CONSTRAINT uq_eam_tline_code UNIQUE (company_id, code),
    CONSTRAINT uq_eam_tline_asset_id UNIQUE (company_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_eam_tline_region ON eam_transmission_line (region_id);
DROP TRIGGER IF EXISTS trg_eam_tline_updated_at ON eam_transmission_line;
CREATE TRIGGER trg_eam_tline_updated_at BEFORE UPDATE ON eam_transmission_line FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TABLE IF NOT EXISTS eam_transmission_tower (
    id                   UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                 VARCHAR(200) NOT NULL,
    code                 VARCHAR(32),
    asset_id             VARCHAR(160),
    asset_type_id        UUID         REFERENCES eam_asset_type(id),
    hierarchy_level      INTEGER,
    transmission_line_id UUID         NOT NULL REFERENCES eam_transmission_line(id) ON DELETE CASCADE,
    tower_number         INTEGER      NOT NULL,
    region_id            UUID         REFERENCES eam_region(id) ON DELETE SET NULL,
    voltage_level_id     UUID         REFERENCES eam_voltage_level(id),
    tower_type           VARCHAR(16)  NOT NULL DEFAULT 'lattice_steel',
    tower_function       VARCHAR(16),
    height_m             NUMERIC(10,2),
    base_width_m         NUMERIC(10,2),
    weight_kg            NUMERIC(14,2),
    foundation_type      VARCHAR(120),
    span_to_next_m       NUMERIC(10,2),
    span_to_previous_m   NUMERIC(10,2),
    gps_latitude         NUMERIC(12,7),
    gps_longitude        NUMERIC(12,7),
    elevation_m          NUMERIC(10,2),
    ground_clearance_m   NUMERIC(10,2),
    right_of_way_m       NUMERIC(10,2),
    phase_configuration  VARCHAR(120),
    insulator_type       VARCHAR(12),
    insulator_count      INTEGER,
    earth_wire_attached  BOOLEAN      NOT NULL DEFAULT FALSE,
    aviation_marking     BOOLEAN      NOT NULL DEFAULT FALSE,
    -- TAS conductor block
    tower_span           VARCHAR(60),
    tower_span_length_m  NUMERIC(10,2),
    distance_from_pmu1_m NUMERIC(12,2),
    distance_from_pmu2_m NUMERIC(12,2),
    tti_criticality      VARCHAR(8),
    phasing_top          VARCHAR(120),
    phasing_middle       VARCHAR(120),
    phasing_bottom       VARCHAR(120),
    conductor_type       VARCHAR(60),
    conductor_size_mm2   NUMERIC(12,2),
    conductor_current_rating_a NUMERIC(12,2),
    conductor_arrangement VARCHAR(8),
    conductor_year       INTEGER,
    conductor_brand      VARCHAR(120),
    conductor_make       VARCHAR(120),
    conductor_serial_no  VARCHAR(120),
    -- insulator-detail block
    insulator_disc_per_string INTEGER,
    insulator_year       INTEGER,
    insulator_brand      VARCHAR(120),
    insulator_make       VARCHAR(120),
    insulator_serial_no  VARCHAR(120),
    -- accessory block
    accessory_awl        BOOLEAN      NOT NULL DEFAULT FALSE,
    accessory_acws       BOOLEAN      NOT NULL DEFAULT FALSE,
    accessory_acd        BOOLEAN      NOT NULL DEFAULT FALSE,
    accessory_year       INTEGER,
    accessory_brand      VARCHAR(120),
    accessory_make       VARCHAR(120),
    accessory_serial_no  VARCHAR(120),
    operational_status   VARCHAR(16)  NOT NULL DEFAULT 'operational',
    condition_status     VARCHAR(12)  NOT NULL DEFAULT 'good',
    last_inspection_date DATE,
    next_inspection_date DATE,
    -- WayleaveMixin (§3.12)
    span_rata            VARCHAR(4),
    span_bukit           VARCHAR(4),
    span_gaung           VARCHAR(4),
    road_crossing        VARCHAR(120),
    river_crossing       VARCHAR(120),
    locality             VARCHAR(160),
    landowner            VARCHAR(160),
    activity             VARCHAR(160),
    danger_tree          VARCHAR(4),
    occupational_permit  VARCHAR(120),
    safety_signage       VARCHAR(4),
    image                TEXT,
    notes                TEXT,
    active               BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id           UUID         REFERENCES companies(id),
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_tower_type CHECK (tower_type IN ('lattice_steel','tubular_steel','wood_pole','concrete_pole','monopole','h_frame')),
    CONSTRAINT chk_eam_tower_func CHECK (tower_function IS NULL OR tower_function IN ('suspension','tension','angle','dead_end','transposition','junction')),
    CONSTRAINT chk_eam_tower_ins CHECK (insulator_type IS NULL OR insulator_type IN ('glass','porcelain','composite')),
    CONSTRAINT chk_eam_tower_arr CHECK (conductor_arrangement IS NULL OR conductor_arrangement IN ('single','double')),
    CONSTRAINT chk_eam_tower_tti CHECK (tti_criticality IS NULL OR tti_criticality IN ('tca','tnca')),
    CONSTRAINT chk_eam_tower_opstat CHECK (operational_status IN ('operational','standby','out_of_service','under_repair','decommissioned')),
    CONSTRAINT chk_eam_tower_cond CHECK (condition_status IN ('excellent','good','fair','poor','critical')),
    CONSTRAINT chk_eam_tower_rata CHECK (span_rata IS NULL OR span_rata IN ('yes','no','na')),
    CONSTRAINT chk_eam_tower_bukit CHECK (span_bukit IS NULL OR span_bukit IN ('yes','no','na')),
    CONSTRAINT chk_eam_tower_gaung CHECK (span_gaung IS NULL OR span_gaung IN ('yes','no','na')),
    CONSTRAINT chk_eam_tower_tree CHECK (danger_tree IS NULL OR danger_tree IN ('yes','no','na')),
    CONSTRAINT chk_eam_tower_sign CHECK (safety_signage IS NULL OR safety_signage IN ('yes','no','na')),
    CONSTRAINT uq_eam_tower_code UNIQUE (company_id, code)
);
CREATE INDEX IF NOT EXISTS idx_eam_tower_line ON eam_transmission_tower (transmission_line_id, tower_number);
DROP TRIGGER IF EXISTS trg_eam_tower_updated_at ON eam_transmission_tower;
CREATE TRIGGER trg_eam_tower_updated_at BEFORE UPDATE ON eam_transmission_tower FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TABLE IF NOT EXISTS eam_transmission_span (
    id                   UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                 VARCHAR(200),
    code                 VARCHAR(32),
    transmission_line_id UUID         NOT NULL REFERENCES eam_transmission_line(id) ON DELETE CASCADE,
    from_tower_id        UUID         NOT NULL REFERENCES eam_transmission_tower(id) ON DELETE CASCADE,
    to_tower_id          UUID         NOT NULL REFERENCES eam_transmission_tower(id) ON DELETE CASCADE,
    from_tower_number    INTEGER,
    to_tower_number      INTEGER,
    region_id            UUID         REFERENCES eam_region(id) ON DELETE SET NULL,
    voltage_level_id     UUID         REFERENCES eam_voltage_level(id),
    asset_id             VARCHAR(160),
    asset_type_id        UUID         REFERENCES eam_asset_type(id),
    hierarchy_level      INTEGER,
    length_m             NUMERIC(12,2),
    sag_m                NUMERIC(10,2),
    ground_clearance_m   NUMERIC(10,2),
    operational_status   VARCHAR(16)  NOT NULL DEFAULT 'operational',
    condition_status     VARCHAR(12)  NOT NULL DEFAULT 'good',
    notes                TEXT,
    active               BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id           UUID         REFERENCES companies(id),
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_span_opstat CHECK (operational_status IN ('operational','standby','out_of_service','under_repair','decommissioned')),
    CONSTRAINT chk_eam_span_cond CHECK (condition_status IN ('excellent','good','fair','poor','critical'))
);
CREATE INDEX IF NOT EXISTS idx_eam_span_line ON eam_transmission_span (transmission_line_id);
DROP TRIGGER IF EXISTS trg_eam_span_updated_at ON eam_transmission_span;
CREATE TRIGGER trg_eam_span_updated_at BEFORE UPDATE ON eam_transmission_span FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TABLE IF NOT EXISTS eam_gantry (
    id                   UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                 VARCHAR(200) NOT NULL,
    code                 VARCHAR(32),
    bay_id               UUID         NOT NULL REFERENCES eam_bay(id) ON DELETE CASCADE,
    transmission_line_id UUID         NOT NULL REFERENCES eam_transmission_line(id) ON DELETE CASCADE,
    substation_id        UUID         REFERENCES eam_substation(id) ON DELETE SET NULL,
    region_id            UUID         REFERENCES eam_region(id) ON DELETE SET NULL,
    voltage_level_id     UUID         REFERENCES eam_voltage_level(id),
    asset_id             VARCHAR(160),
    asset_type_id        UUID         REFERENCES eam_asset_type(id),
    hierarchy_level      INTEGER,
    gantry_type          VARCHAR(12),
    height_m             NUMERIC(10,2),
    span_width_m         NUMERIC(10,2),
    gps_latitude         NUMERIC(12,7),
    gps_longitude        NUMERIC(12,7),
    operational_status   VARCHAR(16)  NOT NULL DEFAULT 'operational',
    condition_status     VARCHAR(12)  NOT NULL DEFAULT 'good',
    commissioning_date   DATE,
    notes                TEXT,
    active               BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id           UUID         REFERENCES companies(id),
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_gantry_type CHECK (gantry_type IS NULL OR gantry_type IN ('strain','dead_end','portal','pole')),
    CONSTRAINT chk_eam_gantry_opstat CHECK (operational_status IN ('operational','standby','out_of_service','under_repair','decommissioned')),
    CONSTRAINT chk_eam_gantry_cond CHECK (condition_status IN ('excellent','good','fair','poor','critical'))
);
CREATE INDEX IF NOT EXISTS idx_eam_gantry_bay ON eam_gantry (bay_id);
DROP TRIGGER IF EXISTS trg_eam_gantry_updated_at ON eam_gantry;
CREATE TRIGGER trg_eam_gantry_updated_at BEFORE UPDATE ON eam_gantry FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- Underground-cable line (§3.5)
-- ============================================================================
CREATE TABLE IF NOT EXISTS eam_ugc_line (
    id                   UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                 VARCHAR(200) NOT NULL,
    code                 VARCHAR(32),
    asset_id             VARCHAR(120),
    asset_type_id        UUID         REFERENCES eam_asset_type(id),
    hierarchy_level      INTEGER,
    region_id            UUID         NOT NULL REFERENCES eam_region(id) ON DELETE CASCADE,
    voltage_level_id     UUID         NOT NULL REFERENCES eam_voltage_level(id),
    from_substation_id   UUID         REFERENCES eam_substation(id) ON DELETE SET NULL,
    to_substation_id     UUID         REFERENCES eam_substation(id) ON DELETE SET NULL,
    number_of_circuits   INTEGER,
    mva_rating           NUMERIC(14,4),
    total_mva            NUMERIC(14,4),
    distance_km          NUMERIC(12,4),
    length_cct_km_66     NUMERIC(12,4),
    length_cct_km_132    NUMERIC(12,4),
    commissioning_date   DATE,
    commission_year      INTEGER,
    design_life_years    INTEGER      NOT NULL DEFAULT 40,
    state                VARCHAR(16)  NOT NULL DEFAULT 'operational',
    ownership            VARCHAR(12)  NOT NULL DEFAULT 'sesb',
    notes                TEXT,
    active               BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id           UUID         REFERENCES companies(id),
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_ugc_state CHECK (state IN ('planning','construction','operational','maintenance','decommissioned')),
    CONSTRAINT chk_eam_ugc_owner CHECK (ownership IN ('sesb','ipp','shared')),
    CONSTRAINT uq_eam_ugc_code UNIQUE (company_id, code),
    CONSTRAINT uq_eam_ugc_asset_id UNIQUE (company_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_eam_ugc_region ON eam_ugc_line (region_id);
DROP TRIGGER IF EXISTS trg_eam_ugc_updated_at ON eam_ugc_line;
CREATE TRIGGER trg_eam_ugc_updated_at BEFORE UPDATE ON eam_ugc_line FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- Underground cable segment + IR/PI test (§3.4)
-- ============================================================================
CREATE TABLE IF NOT EXISTS eam_cable_segment (
    id                   UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                 VARCHAR(200) NOT NULL,
    code                 VARCHAR(32)  NOT NULL,
    sequence             INTEGER      NOT NULL DEFAULT 0,
    distribution_line_id UUID         NOT NULL REFERENCES eam_distribution_line(id) ON DELETE CASCADE,
    voltage_level_id     UUID         REFERENCES eam_voltage_level(id),
    start_substation_id  UUID         REFERENCES eam_substation(id) ON DELETE SET NULL,
    end_substation_id    UUID         REFERENCES eam_substation(id) ON DELETE SET NULL,
    start_chainage_m     NUMERIC(12,2),
    end_chainage_m       NUMERIC(12,2),
    length_m             NUMERIC(12,2),
    cable_type           VARCHAR(8),
    conductor_size       VARCHAR(60),
    laying_method        VARCHAR(16),
    joint_count          INTEGER,
    termination_count    INTEGER,
    risk_area            VARCHAR(16),
    commissioning_date   DATE,
    condition            VARCHAR(12),
    notes                TEXT,
    active               BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id           UUID         REFERENCES companies(id),
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_cseg_cable CHECK (cable_type IS NULL OR cable_type IN ('xlpe','pilc','epr','other')),
    CONSTRAINT chk_eam_cseg_lay CHECK (laying_method IS NULL OR laying_method IN ('direct_buried','duct','tray','trench','submarine')),
    CONSTRAINT chk_eam_cseg_risk CHECK (risk_area IS NULL OR risk_area IN ('normal','high_excavation','vip','flood_prone','coastal')),
    CONSTRAINT chk_eam_cseg_cond CHECK (condition IS NULL OR condition IN ('good','medium','poor','very_poor')),
    CONSTRAINT uq_eam_cseg_code UNIQUE (company_id, code)
);
CREATE INDEX IF NOT EXISTS idx_eam_cseg_line ON eam_cable_segment (distribution_line_id, sequence);
DROP TRIGGER IF EXISTS trg_eam_cseg_updated_at ON eam_cable_segment;
CREATE TRIGGER trg_eam_cseg_updated_at BEFORE UPDATE ON eam_cable_segment FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TABLE IF NOT EXISTS eam_cable_test (
    id                   UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                 VARCHAR(60),
    segment_id           UUID         NOT NULL REFERENCES eam_cable_segment(id) ON DELETE CASCADE,
    distribution_line_id UUID         REFERENCES eam_distribution_line(id) ON DELETE SET NULL,
    voltage_level_id     UUID         REFERENCES eam_voltage_level(id),
    test_date            DATE         NOT NULL,
    test_type            VARCHAR(12)  NOT NULL DEFAULT 'ir',
    tester_id            UUID         REFERENCES users(id),
    ir_30s               NUMERIC(14,4),
    ir_60s               NUMERIC(14,4),
    ir_1min              NUMERIC(14,4),
    ir_10min             NUMERIC(14,4),
    polarization_index   NUMERIC(10,4),
    dar_ratio            NUMERIC(10,4),
    breakdown_voltage_kv NUMERIC(12,4),
    tan_delta_pct        NUMERIC(10,4),
    pd_picocoulomb       NUMERIC(14,4),
    result               VARCHAR(10),
    notes                TEXT,
    company_id           UUID         REFERENCES companies(id),
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_ctest_type CHECK (test_type IN ('ir','hipot','vlf','tandelta','pd')),
    CONSTRAINT chk_eam_ctest_result CHECK (result IS NULL OR result IN ('pass','marginal','fail'))
);
CREATE INDEX IF NOT EXISTS idx_eam_ctest_segment ON eam_cable_test (segment_id, test_date DESC);

-- ============================================================================
-- Wire equipment network-parent FKs now that the targets exist (§3.2)
-- ============================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_eam_equip_tower') THEN
        ALTER TABLE eam_equipment ADD CONSTRAINT fk_eam_equip_tower FOREIGN KEY (tower_id) REFERENCES eam_transmission_tower(id) ON DELETE SET NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_eam_equip_tline') THEN
        ALTER TABLE eam_equipment ADD CONSTRAINT fk_eam_equip_tline FOREIGN KEY (transmission_line_id) REFERENCES eam_transmission_line(id) ON DELETE SET NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_eam_equip_dline') THEN
        ALTER TABLE eam_equipment ADD CONSTRAINT fk_eam_equip_dline FOREIGN KEY (distribution_line_id) REFERENCES eam_distribution_line(id) ON DELETE SET NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_eam_equip_gantry') THEN
        ALTER TABLE eam_equipment ADD CONSTRAINT fk_eam_equip_gantry FOREIGN KEY (gantry_id) REFERENCES eam_gantry(id) ON DELETE SET NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_eam_equip_span') THEN
        ALTER TABLE eam_equipment ADD CONSTRAINT fk_eam_equip_span FOREIGN KEY (span_id) REFERENCES eam_transmission_span(id) ON DELETE SET NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_eam_equip_ugc') THEN
        ALTER TABLE eam_equipment ADD CONSTRAINT fk_eam_equip_ugc FOREIGN KEY (ugc_line_id) REFERENCES eam_ugc_line(id) ON DELETE SET NULL;
    END IF;
END$$;

-- ============================================================================
-- Runtime role grants
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON
            eam_distribution_line, eam_transmission_line, eam_transmission_tower,
            eam_transmission_span, eam_gantry, eam_ugc_line, eam_cable_segment, eam_cable_test
            TO vortex_runtime';
    END IF;
END$$;
