-- Migration: SESB EAM operations (§3.6–3.7)
--
-- Phase 4 — maintenance work orders + the checklist system, defects,
-- inspections, condition monitoring, line patrols, outages, vegetation
-- sections and Cerdik troubleshooting rules. Maintenance and Defect carry
-- the BoundaryReassignMixin (§3.12). State machines live in the handlers
-- (§5.2/5.4/5.6). plan_id is a plain UUID here; its FK to the plan table
-- is added in Phase 5.

-- ============================================================================
-- Checklist system (templates → items → options; lines on an order)
-- ============================================================================
CREATE TABLE IF NOT EXISTS eam_checklist_template (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                VARCHAR(200) NOT NULL,
    equipment_category  VARCHAR(24)  NOT NULL,
    maintenance_type    VARCHAR(16)  NOT NULL,
    version             INTEGER      NOT NULL DEFAULT 1,
    description         TEXT,
    active              BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id          UUID         REFERENCES companies(id),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
DROP TRIGGER IF EXISTS trg_eam_cltpl_updated_at ON eam_checklist_template;
CREATE TRIGGER trg_eam_cltpl_updated_at BEFORE UPDATE ON eam_checklist_template FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TABLE IF NOT EXISTS eam_checklist_template_item (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    template_id         UUID         NOT NULL REFERENCES eam_checklist_template(id) ON DELETE CASCADE,
    name                VARCHAR(300) NOT NULL,
    description         TEXT,
    sequence            INTEGER      NOT NULL DEFAULT 0,
    section             VARCHAR(120),
    input_type          VARCHAR(16)  NOT NULL DEFAULT 'pass_fail',
    measurement_unit    VARCHAR(40),
    measurement_min     NUMERIC(14,4),
    measurement_max     NUMERIC(14,4),
    rating_scale_max    INTEGER,
    is_required         BOOLEAN      NOT NULL DEFAULT FALSE,
    is_critical         BOOLEAN      NOT NULL DEFAULT FALSE,
    is_scored           BOOLEAN      NOT NULL DEFAULT FALSE,
    weight              NUMERIC(8,4) NOT NULL DEFAULT 1,
    CONSTRAINT chk_eam_clitem_input CHECK (input_type IN ('pass_fail','yes_no','measurement','text','selection','rating'))
);
CREATE INDEX IF NOT EXISTS idx_eam_clitem_tpl ON eam_checklist_template_item (template_id, sequence);

CREATE TABLE IF NOT EXISTS eam_checklist_selection_option (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    template_item_id    UUID         NOT NULL REFERENCES eam_checklist_template_item(id) ON DELETE CASCADE,
    name                VARCHAR(200) NOT NULL,
    value               VARCHAR(120) NOT NULL,
    sequence            INTEGER      NOT NULL DEFAULT 0,
    score_value         NUMERIC(8,2),
    is_fail             BOOLEAN      NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_eam_clopt_item ON eam_checklist_selection_option (template_item_id, sequence);

-- ============================================================================
-- Maintenance order (§3.6) — carries BoundaryReassignMixin
-- ============================================================================
CREATE TABLE IF NOT EXISTS eam_maintenance (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- BoundaryReassignMixin (§3.12)
    responsible_kawasan_id UUID      REFERENCES eam_kawasan(id) ON DELETE SET NULL,
    responsible_region_id  UUID      REFERENCES eam_region(id) ON DELETE SET NULL,
    is_cross_boundary   BOOLEAN      NOT NULL DEFAULT FALSE,
    reassignment_reason TEXT,
    reassigned_by_id    UUID         REFERENCES users(id),
    reassigned_date     TIMESTAMPTZ,
    reassignment_count  INTEGER      NOT NULL DEFAULT 0,
    -- identity
    name                VARCHAR(32),
    description         VARCHAR(300) NOT NULL,
    equipment_id        UUID         NOT NULL REFERENCES eam_equipment(id) ON DELETE CASCADE,
    equipment_category  VARCHAR(24),
    bay_id              UUID         REFERENCES eam_bay(id) ON DELETE SET NULL,
    substation_id       UUID         REFERENCES eam_substation(id) ON DELETE SET NULL,
    site_id             UUID         REFERENCES eam_site(id) ON DELETE SET NULL,
    region_id           UUID         REFERENCES eam_region(id) ON DELETE SET NULL,
    kawasan_id          UUID         REFERENCES eam_kawasan(id) ON DELETE SET NULL,
    maintenance_type    VARCHAR(12)  NOT NULL DEFAULT 'pm',
    priority            VARCHAR(2)   NOT NULL DEFAULT '1',
    request_date        DATE         NOT NULL DEFAULT CURRENT_DATE,
    scheduled_date      DATE,
    scheduled_time      NUMERIC(6,2),
    planned_duration_hours NUMERIC(8,2),
    start_date          TIMESTAMPTZ,
    end_date            TIMESTAMPTZ,
    actual_duration_hours NUMERIC(10,2),
    assigned_to         UUID         REFERENCES users(id),
    field_agent_group_id UUID,
    state               VARCHAR(16)  NOT NULL DEFAULT 'draft',
    accepted_by         UUID         REFERENCES users(id),
    acceptance_date     TIMESTAMPTZ,
    rejected_by         UUID         REFERENCES users(id),
    rejection_date      TIMESTAMPTZ,
    rejection_reason    TEXT,
    rejection_count     INTEGER      NOT NULL DEFAULT 0,
    verified_by         UUID         REFERENCES users(id),
    verification_date   TIMESTAMPTZ,
    verification_notes  TEXT,
    verification_rating VARCHAR(12),
    needs_rework        BOOLEAN      NOT NULL DEFAULT FALSE,
    rework_notes        TEXT,
    rework_count        INTEGER      NOT NULL DEFAULT 0,
    work_description    TEXT,
    findings            TEXT,
    actions_taken       TEXT,
    recommendations     TEXT,
    signature           TEXT,
    signed_by_name      VARCHAR(160),
    signature_date      TIMESTAMPTZ,
    materials_cost      NUMERIC(16,2) NOT NULL DEFAULT 0,
    labor_cost          NUMERIC(16,2) NOT NULL DEFAULT 0,
    total_cost          NUMERIC(16,2) NOT NULL DEFAULT 0,
    parent_maintenance_id UUID       REFERENCES eam_maintenance(id) ON DELETE SET NULL,
    plan_id             UUID,
    checklist_template_id UUID       REFERENCES eam_checklist_template(id) ON DELETE SET NULL,
    escalation_level    INTEGER      NOT NULL DEFAULT 0,
    last_escalated_on   TIMESTAMPTZ,
    repair_for_defect_id UUID,
    is_consolidated     BOOLEAN      NOT NULL DEFAULT FALSE,
    notes               TEXT,
    active              BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id          UUID         REFERENCES companies(id),
    created_by          UUID         REFERENCES users(id),
    updated_by          UUID         REFERENCES users(id),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_mnt_type CHECK (maintenance_type IN ('pm','cm','emergency','inspection','testing','overhaul')),
    CONSTRAINT chk_eam_mnt_priority CHECK (priority IN ('0','1','2','3')),
    CONSTRAINT chk_eam_mnt_state CHECK (state IN ('draft','scheduled','assigned','in_progress','on_hold','completed','verified','cancelled')),
    CONSTRAINT chk_eam_mnt_rating CHECK (verification_rating IS NULL OR verification_rating IN ('poor','fair','good','excellent'))
);
CREATE INDEX IF NOT EXISTS idx_eam_mnt_equip ON eam_maintenance (equipment_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_eam_mnt_state ON eam_maintenance (state);
CREATE INDEX IF NOT EXISTS idx_eam_mnt_sched ON eam_maintenance (scheduled_date);
CREATE INDEX IF NOT EXISTS idx_eam_mnt_assignee ON eam_maintenance (assigned_to);
DROP TRIGGER IF EXISTS trg_eam_mnt_updated_at ON eam_maintenance;
CREATE TRIGGER trg_eam_mnt_updated_at BEFORE UPDATE ON eam_maintenance FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TABLE IF NOT EXISTS eam_maintenance_part_line (
    id                  UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    maintenance_id      UUID          NOT NULL REFERENCES eam_maintenance(id) ON DELETE CASCADE,
    sequence            INTEGER       NOT NULL DEFAULT 0,
    part_id             UUID          REFERENCES eam_part(id) ON DELETE SET NULL,
    name                VARCHAR(200)  NOT NULL,
    part_number         VARCHAR(120),
    quantity            NUMERIC(14,4) NOT NULL DEFAULT 1,
    unit                VARCHAR(40),
    unit_cost           NUMERIC(16,4) NOT NULL DEFAULT 0,
    cost                NUMERIC(16,4) NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_eam_mntpart_order ON eam_maintenance_part_line (maintenance_id);

-- Checklist line — instantiated on an order from a template item
CREATE TABLE IF NOT EXISTS eam_checklist_line (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    maintenance_id      UUID         NOT NULL REFERENCES eam_maintenance(id) ON DELETE CASCADE,
    template_item_id    UUID         REFERENCES eam_checklist_template_item(id) ON DELETE SET NULL,
    name                VARCHAR(300) NOT NULL,
    description         TEXT,
    sequence            INTEGER      NOT NULL DEFAULT 0,
    section             VARCHAR(120),
    input_type          VARCHAR(16)  NOT NULL DEFAULT 'pass_fail',
    measurement_unit    VARCHAR(40),
    measurement_min     NUMERIC(14,4),
    measurement_max     NUMERIC(14,4),
    selection_options   TEXT,
    rating_scale_max    INTEGER,
    is_required         BOOLEAN      NOT NULL DEFAULT FALSE,
    is_critical         BOOLEAN      NOT NULL DEFAULT FALSE,
    is_scored           BOOLEAN      NOT NULL DEFAULT FALSE,
    weight              NUMERIC(8,4) NOT NULL DEFAULT 1,
    value_pass_fail     VARCHAR(4),
    value_yes_no        VARCHAR(4),
    value_measurement   NUMERIC(14,4),
    value_text          TEXT,
    value_selection     VARCHAR(120),
    value_rating        INTEGER,
    note                TEXT,
    photo               TEXT,
    CONSTRAINT chk_eam_clline_pf CHECK (value_pass_fail IS NULL OR value_pass_fail IN ('pass','fail','na')),
    CONSTRAINT chk_eam_clline_yn CHECK (value_yes_no IS NULL OR value_yes_no IN ('yes','no'))
);
CREATE INDEX IF NOT EXISTS idx_eam_clline_order ON eam_checklist_line (maintenance_id, sequence);

-- ============================================================================
-- Defect (§3.7) — carries BoundaryReassignMixin
-- ============================================================================
CREATE TABLE IF NOT EXISTS eam_defect (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    responsible_kawasan_id UUID      REFERENCES eam_kawasan(id) ON DELETE SET NULL,
    responsible_region_id  UUID      REFERENCES eam_region(id) ON DELETE SET NULL,
    is_cross_boundary   BOOLEAN      NOT NULL DEFAULT FALSE,
    reassignment_reason TEXT,
    reassigned_by_id    UUID         REFERENCES users(id),
    reassigned_date     TIMESTAMPTZ,
    reassignment_count  INTEGER      NOT NULL DEFAULT 0,
    name                VARCHAR(32),
    title               VARCHAR(300) NOT NULL,
    description         TEXT,
    source_maintenance_id UUID       REFERENCES eam_maintenance(id) ON DELETE SET NULL,
    source_checklist_line_id UUID    REFERENCES eam_checklist_line(id) ON DELETE SET NULL,
    source_inspection_id UUID,
    source_patrol_id    UUID,
    equipment_id        UUID         NOT NULL REFERENCES eam_equipment(id) ON DELETE CASCADE,
    bay_id              UUID         REFERENCES eam_bay(id) ON DELETE SET NULL,
    substation_id       UUID         REFERENCES eam_substation(id) ON DELETE SET NULL,
    site_id             UUID         REFERENCES eam_site(id) ON DELETE SET NULL,
    region_id           UUID         REFERENCES eam_region(id) ON DELETE SET NULL,
    kawasan_id          UUID         REFERENCES eam_kawasan(id) ON DELETE SET NULL,
    discovered_date     TIMESTAMPTZ,
    discovered_by       UUID         REFERENCES users(id),
    severity            VARCHAR(12)  NOT NULL DEFAULT 'moderate',
    defect_category     VARCHAR(16),
    state               VARCHAR(12)  NOT NULL DEFAULT 'draft',
    photo_before        TEXT,
    photo_before_filename VARCHAR(200),
    photo_after         TEXT,
    photo_after_filename VARCHAR(200),
    assigned_to         UUID         REFERENCES users(id),
    repair_maintenance_id UUID       REFERENCES eam_maintenance(id) ON DELETE SET NULL,
    repaired_by         UUID         REFERENCES users(id),
    repair_date         TIMESTAMPTZ,
    repair_notes        TEXT,
    verified_by         UUID         REFERENCES users(id),
    verification_date   TIMESTAMPTZ,
    verification_notes  TEXT,
    active              BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id          UUID         REFERENCES companies(id),
    created_by          UUID         REFERENCES users(id),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_defect_sev CHECK (severity IN ('minor','moderate','major','critical')),
    CONSTRAINT chk_eam_defect_cat CHECK (defect_category IS NULL OR defect_category IN ('electrical','mechanical','structural','safety','housekeeping','other')),
    CONSTRAINT chk_eam_defect_state CHECK (state IN ('draft','open','assigned','in_repair','repaired','verified','cancelled'))
);
CREATE INDEX IF NOT EXISTS idx_eam_defect_equip ON eam_defect (equipment_id);
CREATE INDEX IF NOT EXISTS idx_eam_defect_state ON eam_defect (state);
DROP TRIGGER IF EXISTS trg_eam_defect_updated_at ON eam_defect;
CREATE TRIGGER trg_eam_defect_updated_at BEFORE UPDATE ON eam_defect FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- Inspection (§3.7)
-- ============================================================================
CREATE TABLE IF NOT EXISTS eam_inspection (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                VARCHAR(32),
    equipment_id        UUID         NOT NULL REFERENCES eam_equipment(id) ON DELETE CASCADE,
    equipment_category  VARCHAR(24),
    bay_id              UUID         REFERENCES eam_bay(id) ON DELETE SET NULL,
    substation_id       UUID         REFERENCES eam_substation(id) ON DELETE SET NULL,
    inspection_type     VARCHAR(12)  NOT NULL DEFAULT 'routine',
    inspection_date     DATE         NOT NULL,
    inspector_id        UUID         REFERENCES users(id),
    maintenance_id      UUID         REFERENCES eam_maintenance(id) ON DELETE SET NULL,
    state               VARCHAR(12)  NOT NULL DEFAULT 'draft',
    overall_condition   VARCHAR(12),
    condition_score     INTEGER,
    visual_check        VARCHAR(12),
    cleanliness_check   VARCHAR(12),
    corrosion_check     VARCHAR(12),
    oil_leak_check      VARCHAR(12),
    connection_check    VARCHAR(12),
    labeling_check      VARCHAR(12),
    temperature_c       NUMERIC(8,2),
    humidity_percent    NUMERIC(8,2),
    noise_level_db      NUMERIC(8,2),
    findings            TEXT,
    defects_found       TEXT,
    recommendations     TEXT,
    immediate_action_required BOOLEAN NOT NULL DEFAULT FALSE,
    notes               TEXT,
    active              BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id          UUID         REFERENCES companies(id),
    approved_by         UUID         REFERENCES users(id),
    approved_date       DATE,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_insp_type CHECK (inspection_type IN ('routine','detailed','visual','thermal','ultrasonic','special')),
    CONSTRAINT chk_eam_insp_state CHECK (state IN ('draft','in_progress','completed','approved')),
    CONSTRAINT chk_eam_insp_cond CHECK (overall_condition IS NULL OR overall_condition IN ('excellent','good','fair','poor','critical'))
);
CREATE INDEX IF NOT EXISTS idx_eam_insp_equip ON eam_inspection (equipment_id, inspection_date DESC);
DROP TRIGGER IF EXISTS trg_eam_insp_updated_at ON eam_inspection;
CREATE TRIGGER trg_eam_insp_updated_at BEFORE UPDATE ON eam_inspection FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- Condition monitoring (§3.7)
-- ============================================================================
CREATE TABLE IF NOT EXISTS eam_condition_monitoring (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                VARCHAR(32),
    equipment_id        UUID         NOT NULL REFERENCES eam_equipment(id) ON DELETE CASCADE,
    equipment_category  VARCHAR(24),
    test_type           VARCHAR(20)  NOT NULL DEFAULT 'dga',
    test_date           DATE         NOT NULL,
    test_time           NUMERIC(6,2),
    tested_by           UUID         REFERENCES users(id),
    test_lab            VARCHAR(160),
    test_report_number  VARCHAR(120),
    state               VARCHAR(12)  NOT NULL DEFAULT 'draft',
    result_status       VARCHAR(12),
    result_summary      TEXT,
    dga_hydrogen_h2     NUMERIC(14,4),
    dga_methane_ch4     NUMERIC(14,4),
    dga_ethane_c2h6     NUMERIC(14,4),
    dga_ethylene_c2h4   NUMERIC(14,4),
    dga_acetylene_c2h2  NUMERIC(14,4),
    dga_carbon_monoxide_co NUMERIC(14,4),
    dga_carbon_dioxide_co2 NUMERIC(14,4),
    dga_oxygen_o2       NUMERIC(14,4),
    dga_nitrogen_n2     NUMERIC(14,4),
    dga_fault_type      VARCHAR(8),
    oil_bdv_kv          NUMERIC(12,4),
    oil_moisture_ppm    NUMERIC(12,4),
    oil_acidity_mg_koh  NUMERIC(12,4),
    oil_ift_mn_m        NUMERIC(12,4),
    oil_color           NUMERIC(8,2),
    oil_tan_delta       NUMERIC(12,6),
    oil_pcb_ppm         NUMERIC(12,4),
    thermal_ambient_temp_c NUMERIC(8,2),
    thermal_max_temp_c  NUMERIC(8,2),
    thermal_hot_spot_location VARCHAR(160),
    thermal_image       TEXT,
    thermal_severity    VARCHAR(16),
    pd_magnitude_pc     NUMERIC(14,4),
    pd_repetition_rate  NUMERIC(14,4),
    pd_location         VARCHAR(160),
    pd_pattern          VARCHAR(12),
    ir_1min_mohm        NUMERIC(14,4),
    ir_10min_mohm       NUMERIC(14,4),
    sf6_purity_percent  NUMERIC(8,4),
    sf6_moisture_ppm    NUMERIC(12,4),
    sf6_so2_ppm         NUMERIC(12,4),
    sf6_pressure_bar    NUMERIC(10,4),
    contact_resistance_micro_ohm NUMERIC(14,4),
    closing_time_ms     NUMERIC(10,2),
    opening_time_ms     NUMERIC(10,2),
    battery_capacity_percent NUMERIC(8,2),
    battery_internal_resistance_mohm NUMERIC(12,4),
    battery_discharge_time_hours NUMERIC(10,2),
    notes               TEXT,
    recommendations     TEXT,
    active              BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id          UUID         REFERENCES companies(id),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_cm_type CHECK (test_type IN ('dga','thermal','pd','oil_quality','tan_delta','winding_resistance','ir','sf6','contact_resistance','battery','timing')),
    CONSTRAINT chk_eam_cm_state CHECK (state IN ('draft','submitted','reviewed')),
    CONSTRAINT chk_eam_cm_result CHECK (result_status IS NULL OR result_status IN ('normal','caution','warning','critical'))
);
CREATE INDEX IF NOT EXISTS idx_eam_cm_equip ON eam_condition_monitoring (equipment_id, test_date DESC);
DROP TRIGGER IF EXISTS trg_eam_cm_updated_at ON eam_condition_monitoring;
CREATE TRIGGER trg_eam_cm_updated_at BEFORE UPDATE ON eam_condition_monitoring FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- Line patrol (§3.7)
-- ============================================================================
CREATE TABLE IF NOT EXISTS eam_line_patrol (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                VARCHAR(32),
    distribution_line_id UUID        REFERENCES eam_distribution_line(id) ON DELETE CASCADE,
    transmission_line_id UUID        REFERENCES eam_transmission_line(id) ON DELETE CASCADE,
    patrol_type         VARCHAR(12)  NOT NULL DEFAULT 'routine',
    patrol_date         DATE         NOT NULL,
    patrol_method       VARCHAR(12),
    from_tower_id       UUID         REFERENCES eam_transmission_tower(id) ON DELETE SET NULL,
    to_tower_id         UUID         REFERENCES eam_transmission_tower(id) ON DELETE SET NULL,
    route_description   TEXT,
    span_count          INTEGER,
    distance_km         NUMERIC(12,4),
    patroller_id        UUID         REFERENCES users(id),
    weather             VARCHAR(120),
    anomalies_found     INTEGER,
    vegetation_issues   INTEGER,
    tower_issues        INTEGER,
    conductor_issues    INTEGER,
    insulator_issues    INTEGER,
    hardware_issues     INTEGER,
    findings            TEXT,
    state               VARCHAR(12)  NOT NULL DEFAULT 'draft',
    reviewed_by         UUID         REFERENCES users(id),
    review_date         TIMESTAMPTZ,
    review_notes        TEXT,
    notes               TEXT,
    active              BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id          UUID         REFERENCES companies(id),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_patrol_type CHECK (patrol_type IN ('routine','cbm','storm','vegetation','emergency')),
    CONSTRAINT chk_eam_patrol_method CHECK (patrol_method IS NULL OR patrol_method IN ('ground','vehicle','uav','climbing','helicopter')),
    CONSTRAINT chk_eam_patrol_state CHECK (state IN ('draft','in_progress','completed','reviewed','cancelled'))
);
DROP TRIGGER IF EXISTS trg_eam_patrol_updated_at ON eam_line_patrol;
CREATE TRIGGER trg_eam_patrol_updated_at BEFORE UPDATE ON eam_line_patrol FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- Outage (§3.7) — SAIDI/SAIFI source
-- ============================================================================
CREATE TABLE IF NOT EXISTS eam_outage (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                VARCHAR(32),
    substation_id       UUID         NOT NULL REFERENCES eam_substation(id) ON DELETE CASCADE,
    feeder              VARCHAR(120),
    region_id           UUID         REFERENCES eam_region(id) ON DELETE SET NULL,
    zon_id              UUID         REFERENCES eam_zon(id) ON DELETE SET NULL,
    kawasan_id          UUID         REFERENCES eam_kawasan(id) ON DELETE SET NULL,
    voltage_kv          NUMERIC(12,4),
    outage_type         VARCHAR(12)  NOT NULL DEFAULT 'unplanned',
    cause_category      VARCHAR(20),
    cause_detail        TEXT,
    start_datetime      TIMESTAMPTZ  NOT NULL,
    end_datetime        TIMESTAMPTZ,
    customers_affected  INTEGER      NOT NULL DEFAULT 0,
    state               VARCHAR(12)  NOT NULL DEFAULT 'ongoing',
    is_major_event      BOOLEAN      NOT NULL DEFAULT FALSE,
    equipment_id        UUID         REFERENCES eam_equipment(id) ON DELETE SET NULL,
    maintenance_id      UUID         REFERENCES eam_maintenance(id) ON DELETE SET NULL,
    description         TEXT,
    notes               TEXT,
    company_id          UUID         REFERENCES companies(id),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_outage_type CHECK (outage_type IN ('planned','unplanned','emergency')),
    CONSTRAINT chk_eam_outage_cause CHECK (cause_category IS NULL OR cause_category IN ('equipment_failure','weather','vegetation','third_party','animal','overload','human_error','unknown')),
    CONSTRAINT chk_eam_outage_state CHECK (state IN ('ongoing','restored','cancelled'))
);
CREATE INDEX IF NOT EXISTS idx_eam_outage_sub ON eam_outage (substation_id, start_datetime DESC);
CREATE INDEX IF NOT EXISTS idx_eam_outage_start ON eam_outage (start_datetime DESC);
DROP TRIGGER IF EXISTS trg_eam_outage_updated_at ON eam_outage;
CREATE TRIGGER trg_eam_outage_updated_at BEFORE UPDATE ON eam_outage FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- Vegetation section (§3.7)
-- ============================================================================
CREATE TABLE IF NOT EXISTS eam_vegetation_section (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                VARCHAR(160),
    active              BOOLEAN      NOT NULL DEFAULT TRUE,
    division            VARCHAR(16)  NOT NULL DEFAULT 'distribution',
    transmission_line_id UUID        REFERENCES eam_transmission_line(id) ON DELETE CASCADE,
    from_tower_id       UUID         REFERENCES eam_transmission_tower(id) ON DELETE SET NULL,
    to_tower_id         UUID         REFERENCES eam_transmission_tower(id) ON DELETE SET NULL,
    distribution_line_id UUID        REFERENCES eam_distribution_line(id) ON DELETE CASCADE,
    region_id           UUID         REFERENCES eam_region(id) ON DELETE SET NULL,
    voltage_level_id    UUID         REFERENCES eam_voltage_level(id),
    length_m            NUMERIC(12,2),
    terrain             VARCHAR(12),
    vegetation_type     VARCHAR(12),
    growth_rate         VARCHAR(12),
    fire_risk           VARCHAR(8),
    required_clearance_m NUMERIC(10,2),
    actual_clearance_m  NUMERIC(10,2),
    last_cleared_date   DATE,
    trim_cycle_months   INTEGER,
    last_survey_date    DATE,
    survey_method       VARCHAR(12),
    risk_level          VARCHAR(12),
    contractor          VARCHAR(160),
    maintenance_id      UUID         REFERENCES eam_maintenance(id) ON DELETE SET NULL,
    image               TEXT,
    notes               TEXT,
    company_id          UUID         REFERENCES companies(id),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_veg_div CHECK (division IN ('transmission','distribution')),
    CONSTRAINT chk_eam_veg_terrain CHECK (terrain IS NULL OR terrain IN ('flat','hilly','forest','swamp','farmland','urban')),
    CONSTRAINT chk_eam_veg_growth CHECK (growth_rate IS NULL OR growth_rate IN ('slow','moderate','fast')),
    CONSTRAINT chk_eam_veg_fire CHECK (fire_risk IS NULL OR fire_risk IN ('low','medium','high')),
    CONSTRAINT chk_eam_veg_survey CHECK (survey_method IS NULL OR survey_method IN ('foot','drone','helicopter','satellite','lidar'))
);
DROP TRIGGER IF EXISTS trg_eam_veg_updated_at ON eam_vegetation_section;
CREATE TRIGGER trg_eam_veg_updated_at BEFORE UPDATE ON eam_vegetation_section FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- Cerdik troubleshooting rule (§3.7)
-- ============================================================================
CREATE TABLE IF NOT EXISTS eam_troubleshooting_rule (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                VARCHAR(200) NOT NULL,
    active              BOOLEAN      NOT NULL DEFAULT TRUE,
    sequence            INTEGER      NOT NULL DEFAULT 0,
    priority            VARCHAR(2)   NOT NULL DEFAULT '1',
    equipment_category  VARCHAR(24),
    keywords            VARCHAR(400),
    guidance            TEXT         NOT NULL,
    manufacturer_id     UUID         REFERENCES eam_manufacturer(id),
    company_id          UUID         REFERENCES companies(id),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_tsr_priority CHECK (priority IN ('0','1','2'))
);
DROP TRIGGER IF EXISTS trg_eam_tsr_updated_at ON eam_troubleshooting_rule;
CREATE TRIGGER trg_eam_tsr_updated_at BEFORE UPDATE ON eam_troubleshooting_rule FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Wire deferred FKs now that the targets exist.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_eam_aclass_checklist') THEN
        ALTER TABLE eam_asset_class ADD CONSTRAINT fk_eam_aclass_checklist FOREIGN KEY (default_checklist_template_id) REFERENCES eam_checklist_template(id) ON DELETE SET NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_eam_defect_inspection') THEN
        ALTER TABLE eam_defect ADD CONSTRAINT fk_eam_defect_inspection FOREIGN KEY (source_inspection_id) REFERENCES eam_inspection(id) ON DELETE SET NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_eam_defect_patrol') THEN
        ALTER TABLE eam_defect ADD CONSTRAINT fk_eam_defect_patrol FOREIGN KEY (source_patrol_id) REFERENCES eam_line_patrol(id) ON DELETE SET NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_eam_mnt_repair_defect') THEN
        ALTER TABLE eam_maintenance ADD CONSTRAINT fk_eam_mnt_repair_defect FOREIGN KEY (repair_for_defect_id) REFERENCES eam_defect(id) ON DELETE SET NULL;
    END IF;
END$$;

-- Runtime role grants
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON
            eam_checklist_template, eam_checklist_template_item, eam_checklist_selection_option,
            eam_checklist_line, eam_maintenance, eam_maintenance_part_line, eam_defect,
            eam_inspection, eam_condition_monitoring, eam_line_patrol, eam_outage,
            eam_vegetation_section, eam_troubleshooting_rule TO vortex_runtime';
    END IF;
END$$;
