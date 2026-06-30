-- Migration: SESB EAM equipment, components, parts + specializations
--
-- Phase 2 — the core asset records (§3.2) and their 1-to-1 nameplate /
-- test detail tables (§3.3). Equipment carries the asset-verification
-- mixin (§3.12). Computed fields (health_index, age_years, mtbf_days,
-- action_plan_auto, predicted_*, …) are derived on read per §2.3 and are
-- NOT stored.
--
-- Network-parent columns (tower_id, span_id, gantry_id, transmission_/
-- distribution_line_id, ugc_line_id) are plain UUIDs here; their target
-- tables and FKs arrive in Phase 3.

-- ============================================================================
-- Equipment — the central asset table (§3.2)
-- ============================================================================
CREATE TABLE IF NOT EXISTS eam_equipment (
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
    code                  VARCHAR(32),
    asset_id              VARCHAR(160),
    asset_type_id         UUID          REFERENCES eam_asset_type(id),
    hierarchy_level       INTEGER,
    mnec_sequence         INTEGER,
    -- parentage (one of: bay / tower / span / gantry / line / ugc_line)
    bay_id                UUID          REFERENCES eam_bay(id) ON DELETE SET NULL,
    substation_id         UUID          REFERENCES eam_substation(id) ON DELETE SET NULL,
    tower_id              UUID,
    transmission_line_id  UUID,
    distribution_line_id  UUID,
    gantry_id             UUID,
    span_id               UUID,
    ugc_line_id           UUID,
    division              VARCHAR(16),
    equipment_category    VARCHAR(24)   NOT NULL,
    -- classification
    asset_class_id        UUID          REFERENCES eam_asset_class(id),
    asset_class_type      VARCHAR(16),
    asset_class_group     VARCHAR(32),
    asset_tag             VARCHAR(120),
    -- nameplate
    manufacturer_id       UUID          REFERENCES eam_manufacturer(id),
    model_number          VARCHAR(120),
    serial_number         VARCHAR(120),
    manufacture_date      DATE,
    installation_date     DATE,
    commissioning_date    DATE,
    warranty_expiry_date  DATE,
    design_life_years     INTEGER,
    commission_year       INTEGER,
    voltage_level_id      UUID          REFERENCES eam_voltage_level(id),
    rated_voltage_kv      NUMERIC(12,4),
    rated_current_a       NUMERIC(12,2),
    rated_power_kva       NUMERIC(14,2),
    fuse_rating_a         NUMERIC(12,2),
    -- status & condition
    operational_status    VARCHAR(16)   NOT NULL DEFAULT 'operational',
    condition_status      VARCHAR(12)   NOT NULL DEFAULT 'good',
    nomenclature          VARCHAR(200),
    rating                VARCHAR(200),
    -- lifecycle / risk planning
    useful_life_years     INTEGER,
    failure_record        INTEGER       NOT NULL DEFAULT 0,
    risk_level            VARCHAR(12)   NOT NULL DEFAULT 'low',
    target_replacement_year INTEGER,
    ibr_budget_available  BOOLEAN       NOT NULL DEFAULT FALSE,
    ibr_year              INTEGER,
    eqp_qty_required      INTEGER,
    type_equipment_required VARCHAR(200),
    -- media / misc
    qr_code               VARCHAR(160),
    qr_code_image         TEXT,
    image                 TEXT,
    notes                 TEXT,
    active                BOOLEAN       NOT NULL DEFAULT TRUE,
    company_id            UUID          REFERENCES companies(id),
    created_by            UUID          REFERENCES users(id),
    updated_by            UUID          REFERENCES users(id),
    created_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_equip_vstate CHECK (verification_state IN ('draft','submitted','verified','approved','rejected')),
    CONSTRAINT chk_eam_equip_div    CHECK (division IS NULL OR division IN ('transmission','distribution')),
    CONSTRAINT chk_eam_equip_cat    CHECK (equipment_category IN (
        'transformer','switchgear','rmu','motorised_rmu','protection','control_panel','scada','rtu',
        'battery','charger','capacitor','ner','feeder_pillar','recloser','sectionaliser','metering',
        'busbar','isolator','earthing','surge_arrester','cable','elb','cable_bridge','auxiliary','other')),
    CONSTRAINT chk_eam_equip_opstat CHECK (operational_status IN ('operational','standby','out_of_service','under_repair','decommissioned')),
    CONSTRAINT chk_eam_equip_cond   CHECK (condition_status IN ('excellent','good','fair','poor','critical')),
    CONSTRAINT chk_eam_equip_risk   CHECK (risk_level IN ('low','medium','high','critical')),
    CONSTRAINT chk_eam_equip_aclass_type CHECK (asset_class_type IS NULL OR asset_class_type IN ('electrical','non_electrical')),
    CONSTRAINT uq_eam_equip_asset_id UNIQUE (company_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_eam_equip_bay        ON eam_equipment (bay_id);
CREATE INDEX IF NOT EXISTS idx_eam_equip_substation ON eam_equipment (substation_id);
CREATE INDEX IF NOT EXISTS idx_eam_equip_tower      ON eam_equipment (tower_id);
CREATE INDEX IF NOT EXISTS idx_eam_equip_category   ON eam_equipment (equipment_category);
CREATE INDEX IF NOT EXISTS idx_eam_equip_vstate     ON eam_equipment (verification_state);
CREATE INDEX IF NOT EXISTS idx_eam_equip_mfr        ON eam_equipment (manufacturer_id);
DROP TRIGGER IF EXISTS trg_eam_equip_updated_at ON eam_equipment;
CREATE TRIGGER trg_eam_equip_updated_at BEFORE UPDATE ON eam_equipment
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- Component (§3.2)
-- ============================================================================
CREATE TABLE IF NOT EXISTS eam_component (
    id                  UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                VARCHAR(200)  NOT NULL,
    code                VARCHAR(32),
    asset_id            VARCHAR(180),
    asset_type_id       UUID          REFERENCES eam_asset_type(id),
    hierarchy_level     INTEGER,
    phase               VARCHAR(2),
    circuit             VARCHAR(4),
    side                VARCHAR(4),
    mnec_sequence       INTEGER,
    equipment_id        UUID          NOT NULL REFERENCES eam_equipment(id) ON DELETE CASCADE,
    bay_id              UUID          REFERENCES eam_bay(id) ON DELETE SET NULL,
    substation_id       UUID          REFERENCES eam_substation(id) ON DELETE SET NULL,
    component_type      VARCHAR(24)   NOT NULL DEFAULT 'other',
    manufacturer_id     UUID          REFERENCES eam_manufacturer(id),
    model_number        VARCHAR(120),
    serial_number       VARCHAR(120),
    installation_date   DATE,
    warranty_expiry_date DATE,
    design_life_years   INTEGER,
    operational_status  VARCHAR(12)   NOT NULL DEFAULT 'operational',
    condition_status    VARCHAR(12)   NOT NULL DEFAULT 'good',
    position            VARCHAR(120),
    specification       TEXT,
    nomenclature        VARCHAR(200),
    rating              VARCHAR(200),
    brand               VARCHAR(120),
    make_country        VARCHAR(120),
    commissioning_date  DATE,
    useful_life_years   INTEGER,
    failure_record      INTEGER       NOT NULL DEFAULT 0,
    risk_level          VARCHAR(12)   NOT NULL DEFAULT 'low',
    target_replacement_year INTEGER,
    ibr_budget_available BOOLEAN      NOT NULL DEFAULT FALSE,
    ibr_year            INTEGER,
    eqp_qty_required    INTEGER,
    type_equipment_required VARCHAR(200),
    model_ordering_number VARCHAR(160),
    seal_list           VARCHAR(4),
    seal_factor         NUMERIC(8,4),
    repetitive_issue    VARCHAR(4),
    bay_criticality     VARCHAR(16),
    cost_spare_part     VARCHAR(120),
    notes               TEXT,
    active              BOOLEAN       NOT NULL DEFAULT TRUE,
    company_id          UUID          REFERENCES companies(id),
    created_by          UUID          REFERENCES users(id),
    updated_by          UUID          REFERENCES users(id),
    created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_comp_phase CHECK (phase IS NULL OR phase IN ('R','Y','B','N')),
    CONSTRAINT chk_eam_comp_circuit CHECK (circuit IS NULL OR circuit IN ('L1','L2','L3')),
    CONSTRAINT chk_eam_comp_side CHECK (side IS NULL OR side IN ('IN','OUT')),
    CONSTRAINT chk_eam_comp_opstat CHECK (operational_status IN ('operational','degraded','failed','replaced')),
    CONSTRAINT chk_eam_comp_cond CHECK (condition_status IN ('excellent','good','fair','poor','critical')),
    CONSTRAINT chk_eam_comp_risk CHECK (risk_level IN ('low','medium','high','critical')),
    CONSTRAINT chk_eam_comp_seal CHECK (seal_list IS NULL OR seal_list IN ('yes','no')),
    CONSTRAINT chk_eam_comp_repeat CHECK (repetitive_issue IS NULL OR repetitive_issue IN ('yes','no')),
    CONSTRAINT chk_eam_comp_baycrit CHECK (bay_criticality IS NULL OR bay_criticality IN ('critical','non_critical'))
);
CREATE INDEX IF NOT EXISTS idx_eam_comp_equip ON eam_component (equipment_id);
CREATE INDEX IF NOT EXISTS idx_eam_comp_type  ON eam_component (component_type);
DROP TRIGGER IF EXISTS trg_eam_comp_updated_at ON eam_component;
CREATE TRIGGER trg_eam_comp_updated_at BEFORE UPDATE ON eam_component
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- Part (§3.2)
-- ============================================================================
CREATE TABLE IF NOT EXISTS eam_part (
    id                  UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                VARCHAR(200)  NOT NULL,
    code                VARCHAR(32),
    component_id        UUID          NOT NULL REFERENCES eam_component(id) ON DELETE CASCADE,
    equipment_id        UUID          REFERENCES eam_equipment(id) ON DELETE SET NULL,
    part_type           VARCHAR(12)   NOT NULL DEFAULT 'spare',
    part_number         VARCHAR(120),
    manufacturer_id     UUID          REFERENCES eam_manufacturer(id),
    model_number        VARCHAR(120),
    serial_number       VARCHAR(120),
    quantity            INTEGER       NOT NULL DEFAULT 1,
    unit_of_measure     VARCHAR(32),
    reorder_level       INTEGER,
    installation_date   DATE,
    replacement_date    DATE,
    warranty_expiry_date DATE,
    status              VARCHAR(12)   NOT NULL DEFAULT 'installed',
    condition           VARCHAR(8)    NOT NULL DEFAULT 'good',
    specification       TEXT,
    notes               TEXT,
    active              BOOLEAN       NOT NULL DEFAULT TRUE,
    company_id          UUID          REFERENCES companies(id),
    parent_part_id      UUID          REFERENCES eam_part(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_part_type CHECK (part_type IN ('spare','consumable','critical')),
    CONSTRAINT chk_eam_part_status CHECK (status IN ('installed','in_stock','on_order','obsolete')),
    CONSTRAINT chk_eam_part_condition CHECK (condition IN ('new','good','worn','failed'))
);
CREATE INDEX IF NOT EXISTS idx_eam_part_component ON eam_part (component_id);
DROP TRIGGER IF EXISTS trg_eam_part_updated_at ON eam_part;
CREATE TRIGGER trg_eam_part_updated_at BEFORE UPDATE ON eam_part
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- Equipment specializations (1-1 detail records, §3.3)
-- ============================================================================

-- Transformer ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS eam_equipment_transformer (
    id                       UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    equipment_id             UUID NOT NULL UNIQUE REFERENCES eam_equipment(id) ON DELETE CASCADE,
    bil_tx                   INTEGER,
    tx_no                    VARCHAR(40),
    nameplate_voltage_kv     VARCHAR(60),
    make_country             VARCHAR(120),
    mva_rating               NUMERIC(14,4),
    kva_rating               NUMERIC(14,2),
    primary_voltage_kv       NUMERIC(12,4),
    secondary_voltage_kv     NUMERIC(12,4),
    tertiary_voltage_kv      NUMERIC(12,4),
    transformer_type         VARCHAR(16),
    vector_group             VARCHAR(40),
    winding_material         VARCHAR(12),
    phase_count              VARCHAR(2),
    cooling_type             VARCHAR(8),
    tap_changer_type         VARCHAR(12),
    tap_position_min         INTEGER,
    tap_position_max         INTEGER,
    tap_position_current     INTEGER,
    tap_step_voltage         NUMERIC(12,4),
    oltc_make                VARCHAR(120),
    oltc_types               VARCHAR(120),
    oltc_year                INTEGER,
    oltc_serial_no           VARCHAR(120),
    max_tapping              INTEGER,
    nominal_tapping          INTEGER,
    lowest_voltage_kv        NUMERIC(12,4),
    highest_voltage_kv       NUMERIC(12,4),
    oltc_motor_voltage_v     NUMERIC(12,2),
    oltc_motor_capacity_kw   NUMERIC(12,4),
    oltc_resistance_contact  VARCHAR(120),
    oltc_operation_counter   INTEGER,
    oltc_asset_number        VARCHAR(120),
    oil_type                 VARCHAR(12),
    oil_volume_liters        NUMERIC(14,2),
    oil_weight_kg            NUMERIC(14,2),
    total_weight_kg          NUMERIC(14,2),
    impedance_percent        NUMERIC(8,4),
    no_load_loss_kw          NUMERIC(12,4),
    load_loss_kw             NUMERIC(12,4),
    max_ambient_temp_c       NUMERIC(8,2),
    max_winding_temp_rise_c  NUMERIC(8,2),
    max_oil_temp_rise_c      NUMERIC(8,2),
    has_buchholz_relay       BOOLEAN NOT NULL DEFAULT FALSE,
    has_pressure_relief      BOOLEAN NOT NULL DEFAULT FALSE,
    has_wti                  BOOLEAN NOT NULL DEFAULT FALSE,
    has_oti                  BOOLEAN NOT NULL DEFAULT FALSE,
    has_mog                  BOOLEAN NOT NULL DEFAULT FALSE,
    last_dga_date            DATE,
    dga_status               VARCHAR(12),
    CONSTRAINT chk_eam_tx_type CHECK (transformer_type IS NULL OR transformer_type IN ('power','distribution','auto','grounding','auxiliary')),
    CONSTRAINT chk_eam_tx_winding CHECK (winding_material IS NULL OR winding_material IN ('copper','aluminum')),
    CONSTRAINT chk_eam_tx_phase CHECK (phase_count IS NULL OR phase_count IN ('1','3')),
    CONSTRAINT chk_eam_tx_cooling CHECK (cooling_type IS NULL OR cooling_type IN ('onan','onaf','ofaf','ofwf','dry')),
    CONSTRAINT chk_eam_tx_tap CHECK (tap_changer_type IS NULL OR tap_changer_type IN ('none','oltc','offload')),
    CONSTRAINT chk_eam_tx_oil CHECK (oil_type IS NULL OR oil_type IN ('mineral','silicone','synthetic','natural')),
    CONSTRAINT chk_eam_tx_dga CHECK (dga_status IS NULL OR dga_status IN ('normal','caution','warning','critical'))
);

-- Switchgear / Circuit Breaker -----------------------------------------------
CREATE TABLE IF NOT EXISTS eam_equipment_switchgear (
    id                       UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    equipment_id             UUID NOT NULL UNIQUE REFERENCES eam_equipment(id) ON DELETE CASCADE,
    switchgear_type          VARCHAR(16) NOT NULL DEFAULT 'vcb_11kv',
    rated_breaking_current_ka NUMERIC(12,2),
    rated_making_current_ka  NUMERIC(12,2),
    short_time_current_ka    NUMERIC(12,2),
    short_time_duration_s    NUMERIC(8,2),
    insulation_type          VARCHAR(8),
    sf6_pressure_bar         NUMERIC(10,4),
    sf6_pressure_alarm       NUMERIC(10,4),
    sf6_pressure_lockout     NUMERIC(10,4),
    sf6_volume_kg            NUMERIC(10,4),
    last_sf6_refill_date     DATE,
    mechanism_type           VARCHAR(12),
    operation_count          INTEGER,
    max_operations           INTEGER,
    last_operation_date      TIMESTAMPTZ,
    control_voltage_vdc      NUMERIC(10,2),
    motor_voltage_vac        NUMERIC(10,2),
    closing_time_ms          NUMERIC(10,2),
    opening_time_ms          NUMERIC(10,2),
    close_open_time_ms       NUMERIC(10,2),
    position                 VARCHAR(8),
    contact_wear_percent     NUMERIC(8,2),
    last_overhaul_date       DATE,
    next_overhaul_date       DATE,
    CONSTRAINT chk_eam_swg_ins CHECK (insulation_type IS NULL OR insulation_type IN ('sf6','vacuum','air','oil')),
    CONSTRAINT chk_eam_swg_mech CHECK (mechanism_type IS NULL OR mechanism_type IN ('spring','motor','pneumatic','hydraulic','manual')),
    CONSTRAINT chk_eam_swg_pos CHECK (position IS NULL OR position IN ('open','closed','trip','unknown'))
);

-- RMU ------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS eam_equipment_rmu (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    equipment_id        UUID NOT NULL UNIQUE REFERENCES eam_equipment(id) ON DELETE CASCADE,
    rmu_spec            VARCHAR(8) NOT NULL DEFAULT '3+1',
    custom_config       VARCHAR(120),
    rated_fault_current_ka NUMERIC(12,2),
    insulation_medium   VARCHAR(8),
    sf6_pressure_bar    NUMERIC(10,4),
    sf6_filled_date     DATE,
    protection_type     VARCHAR(12),
    cable_box_type      VARCHAR(12),
    enclosure_type      VARCHAR(12),
    ip_rating           VARCHAR(16),
    width_mm            NUMERIC(10,2),
    depth_mm            NUMERIC(10,2),
    height_mm           NUMERIC(10,2),
    weight_kg           NUMERIC(12,2),
    unit_1_type         VARCHAR(8),
    unit_1_position     VARCHAR(8),
    unit_2_type         VARCHAR(8),
    unit_2_position     VARCHAR(8),
    unit_3_type         VARCHAR(8),
    unit_3_position     VARCHAR(8),
    unit_4_type         VARCHAR(8),
    unit_4_position     VARCHAR(8),
    CONSTRAINT chk_eam_rmu_spec CHECK (rmu_spec IN ('2+1','3+0','3+1','4+0','2+2','custom')),
    CONSTRAINT chk_eam_rmu_ins CHECK (insulation_medium IS NULL OR insulation_medium IN ('sf6','solid','air')),
    CONSTRAINT chk_eam_rmu_prot CHECK (protection_type IS NULL OR protection_type IN ('fuse','relay','combined')),
    CONSTRAINT chk_eam_rmu_encl CHECK (enclosure_type IS NULL OR enclosure_type IN ('indoor','outdoor','padmount','pole_mount'))
);

-- Protection -----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS eam_equipment_protection (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    equipment_id        UUID NOT NULL UNIQUE REFERENCES eam_equipment(id) ON DELETE CASCADE,
    relay_model         VARCHAR(120),
    relay_function      VARCHAR(120),
    relay_type          VARCHAR(20),
    pickup_current_a    NUMERIC(12,2),
    time_dial           NUMERIC(8,4),
    curve_type          VARCHAR(24),
    instantaneous_setting_a NUMERIC(12,2),
    instantaneous_time_ms NUMERIC(10,2),
    ct_primary_a        NUMERIC(12,2),
    ct_secondary_a      NUMERIC(12,2),
    vt_primary_v        NUMERIC(12,2),
    vt_secondary_v      NUMERIC(12,2),
    communication_protocol VARCHAR(12),
    ip_address          VARCHAR(45),
    port_number         INTEGER,
    auxiliary_voltage_vdc NUMERIC(10,2),
    last_test_date      DATE,
    next_test_date      DATE,
    test_result         VARCHAR(8),
    trip_count          INTEGER,
    last_trip_date      TIMESTAMPTZ,
    last_trip_cause     TEXT,
    firmware_version    VARCHAR(60),
    firmware_date       DATE,
    CONSTRAINT chk_eam_prot_curve CHECK (curve_type IS NULL OR curve_type IN ('standard_inverse','very_inverse','extremely_inverse','long_time_inverse','definite_time')),
    CONSTRAINT chk_eam_prot_proto CHECK (communication_protocol IS NULL OR communication_protocol IN ('iec61850','dnp3','modbus','iec103','iec101','none')),
    CONSTRAINT chk_eam_prot_result CHECK (test_result IS NULL OR test_result IN ('pass','fail','pending'))
);

-- SCADA / RTU ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS eam_equipment_scada (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    equipment_id        UUID NOT NULL UNIQUE REFERENCES eam_equipment(id) ON DELETE CASCADE,
    device_type         VARCHAR(20) NOT NULL DEFAULT 'rtu',
    ip_address          VARCHAR(45),
    subnet_mask         VARCHAR(45),
    gateway_address     VARCHAR(45),
    mac_address         VARCHAR(24),
    protocol_master     VARCHAR(16),
    protocol_slave      VARCHAR(16),
    rtu_address         INTEGER,
    station_address     INTEGER,
    digital_input_count INTEGER,
    digital_output_count INTEGER,
    analog_input_count  INTEGER,
    analog_output_count INTEGER,
    pulse_counter_count INTEGER,
    connection_status   VARCHAR(8),
    last_communication  TIMESTAMPTZ,
    communication_quality NUMERIC(8,2),
    power_supply_vdc    VARCHAR(4),
    firmware_version    VARCHAR(60),
    software_version    VARCHAR(60),
    last_firmware_update DATE,
    encrypted_communication BOOLEAN NOT NULL DEFAULT FALSE,
    security_level      VARCHAR(8),
    CONSTRAINT chk_eam_scada_dev CHECK (device_type IN ('rtu','gateway','protocol_converter','data_concentrator','hmi','server')),
    CONSTRAINT chk_eam_scada_conn CHECK (connection_status IS NULL OR connection_status IN ('online','offline','degraded')),
    CONSTRAINT chk_eam_scada_sec CHECK (security_level IS NULL OR security_level IN ('low','medium','high'))
);

-- Battery --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS eam_equipment_battery (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    equipment_id        UUID NOT NULL UNIQUE REFERENCES eam_equipment(id) ON DELETE CASCADE,
    dc_voltage          VARCHAR(8) NOT NULL DEFAULT '110vdc',
    battery_type        VARCHAR(8) NOT NULL DEFAULT 'vrla',
    ampere_hour         NUMERIC(12,2),
    autonomy_hours      NUMERIC(10,2),
    cell_count          INTEGER,
    cells_per_string    INTEGER,
    string_count        INTEGER,
    cell_voltage        NUMERIC(8,4),
    charger_type        VARCHAR(16),
    charger_rating_a    NUMERIC(10,2),
    float_voltage_v     NUMERIC(10,2),
    boost_voltage_v     NUMERIC(10,2),
    current_voltage_v   NUMERIC(10,2),
    current_mode        VARCHAR(12),
    temperature_c       NUMERIC(8,2),
    specific_gravity    NUMERIC(8,4),
    state_of_health     NUMERIC(8,2),
    state_of_charge     NUMERIC(8,2),
    last_discharge_test_date DATE,
    last_discharge_test_result VARCHAR(10),
    last_capacity_measured_ah NUMERIC(12,2),
    last_equalizing_charge_date DATE,
    last_water_top_up_date DATE,
    lowest_cell_voltage NUMERIC(8,4),
    highest_cell_voltage NUMERIC(8,4),
    CONSTRAINT chk_eam_batt_dc CHECK (dc_voltage IN ('110vdc','48vdc','30vdc','24vdc')),
    CONSTRAINT chk_eam_batt_type CHECK (battery_type IN ('vrla','nicd','lion','flooded')),
    CONSTRAINT chk_eam_batt_charger CHECK (charger_type IS NULL OR charger_type IN ('float','boost_float','smart')),
    CONSTRAINT chk_eam_batt_mode CHECK (current_mode IS NULL OR current_mode IN ('float','boost','discharge','standby')),
    CONSTRAINT chk_eam_batt_dtest CHECK (last_discharge_test_result IS NULL OR last_discharge_test_result IN ('pass','fail','marginal'))
);

-- Feeder Pillar --------------------------------------------------------------
CREATE TABLE IF NOT EXISTS eam_equipment_feeder_pillar (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    equipment_id        UUID NOT NULL UNIQUE REFERENCES eam_equipment(id) ON DELETE CASCADE,
    pillar_type         VARCHAR(20) NOT NULL DEFAULT 'distribution',
    rated_voltage_v     NUMERIC(10,2),
    rated_fault_current_ka NUMERIC(12,2),
    incoming_ways       INTEGER,
    outgoing_ways       INTEGER,
    spare_ways          INTEGER,
    protection_type     VARCHAR(12),
    incoming_fuse_rating_a NUMERIC(10,2),
    outgoing_fuse_rating_a NUMERIC(10,2),
    enclosure_material  VARCHAR(12),
    ip_rating           VARCHAR(16),
    installation_type   VARCHAR(8),
    width_mm            NUMERIC(10,2),
    depth_mm            NUMERIC(10,2),
    height_mm           NUMERIC(10,2),
    gps_latitude        NUMERIC(12,7),
    gps_longitude       NUMERIC(12,7),
    location_description VARCHAR(200),
    connected_transformer_id UUID REFERENCES eam_equipment_transformer(id) ON DELETE SET NULL,
    supplied_customers  INTEGER,
    has_metering        BOOLEAN NOT NULL DEFAULT FALSE,
    meter_count         INTEGER,
    ct_ratio            VARCHAR(40),
    door_status         VARCHAR(12),
    condition_rating    VARCHAR(20),
    CONSTRAINT chk_eam_fp_type CHECK (pillar_type IN ('distribution','sub_feeder','metering','link_box','service_pillar','street_lighting')),
    CONSTRAINT chk_eam_fp_prot CHECK (protection_type IS NULL OR protection_type IN ('fuse','mccb','mcb','combined')),
    CONSTRAINT chk_eam_fp_mat CHECK (enclosure_material IS NULL OR enclosure_material IN ('steel','stainless','grp','aluminum')),
    CONSTRAINT chk_eam_fp_inst CHECK (installation_type IS NULL OR installation_type IN ('ground','wall','pole')),
    CONSTRAINT chk_eam_fp_door CHECK (door_status IS NULL OR door_status IN ('secured','damaged','missing')),
    CONSTRAINT chk_eam_fp_cond CHECK (condition_rating IS NULL OR condition_rating IN ('good','fair','poor','needs_replacement'))
);

-- Capacitor ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS eam_equipment_capacitor (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    equipment_id        UUID NOT NULL UNIQUE REFERENCES eam_equipment(id) ON DELETE CASCADE,
    capacitance_uf      NUMERIC(14,4),
    rated_power_kvar    NUMERIC(14,2),
    phase_connection    VARCHAR(12),
    bank_configuration  VARCHAR(12),
    number_of_steps     INTEGER,
    number_of_units     INTEGER,
    units_per_phase     INTEGER,
    series_groups       INTEGER,
    parallel_units      INTEGER,
    protection_type     VARCHAR(12),
    has_discharge_resistor BOOLEAN NOT NULL DEFAULT FALSE,
    has_unbalance_protection BOOLEAN NOT NULL DEFAULT FALSE,
    switching_device    VARCHAR(12),
    CONSTRAINT chk_eam_cap_phase CHECK (phase_connection IS NULL OR phase_connection IN ('star','delta','single','double_star')),
    CONSTRAINT chk_eam_cap_bank CHECK (bank_configuration IS NULL OR bank_configuration IN ('single','double','switched','fixed')),
    CONSTRAINT chk_eam_cap_prot CHECK (protection_type IS NULL OR protection_type IN ('fuse','relay','combined')),
    CONSTRAINT chk_eam_cap_switch CHECK (switching_device IS NULL OR switching_device IN ('vcb','contactor','thyristor'))
);

-- NER ------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS eam_equipment_ner (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    equipment_id        UUID NOT NULL UNIQUE REFERENCES eam_equipment(id) ON DELETE CASCADE,
    resistance_ohm      NUMERIC(14,4),
    rated_time_s        NUMERIC(10,2),
    system_voltage_kv   NUMERIC(12,4),
    ner_voltage_kv      NUMERIC(12,4),
    ner_type            VARCHAR(20),
    resistor_material   VARCHAR(20),
    enclosure_type      VARCHAR(8),
    ip_rating           VARCHAR(16),
    transformer_id      UUID REFERENCES eam_equipment_transformer(id) ON DELETE SET NULL,
    last_resistance_test_date DATE,
    last_measured_resistance_ohm NUMERIC(14,4),
    CONSTRAINT chk_eam_ner_type CHECK (ner_type IS NULL OR ner_type IN ('low_resistance','high_resistance','reactance')),
    CONSTRAINT chk_eam_ner_mat CHECK (resistor_material IS NULL OR resistor_material IN ('stainless_steel','cast_iron','nickel_chrome')),
    CONSTRAINT chk_eam_ner_encl CHECK (enclosure_type IS NULL OR enclosure_type IN ('indoor','outdoor'))
);

-- ELB (Earth Link Box) + WayleaveMixin (§3.12) -------------------------------
CREATE TABLE IF NOT EXISTS eam_equipment_elb (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    equipment_id        UUID NOT NULL UNIQUE REFERENCES eam_equipment(id) ON DELETE CASCADE,
    elb_no              VARCHAR(60),
    distance_m          NUMERIC(12,2),
    gps_latitude        NUMERIC(12,6),
    gps_longitude       NUMERIC(12,6),
    elevation_m         NUMERIC(10,2),
    crossbond_joint_type VARCHAR(120),
    crossbond_joint_count INTEGER,
    slipon_joint_type   VARCHAR(120),
    slipon_joint_count  INTEGER,
    -- WayleaveMixin
    span_rata           VARCHAR(4),
    span_bukit          VARCHAR(4),
    span_gaung          VARCHAR(4),
    road_crossing       VARCHAR(120),
    river_crossing      VARCHAR(120),
    locality            VARCHAR(160),
    landowner           VARCHAR(160),
    activity            VARCHAR(160),
    danger_tree         VARCHAR(4),
    occupational_permit VARCHAR(120),
    safety_signage      VARCHAR(4),
    CONSTRAINT chk_eam_elb_rata CHECK (span_rata IS NULL OR span_rata IN ('yes','no','na')),
    CONSTRAINT chk_eam_elb_bukit CHECK (span_bukit IS NULL OR span_bukit IN ('yes','no','na')),
    CONSTRAINT chk_eam_elb_gaung CHECK (span_gaung IS NULL OR span_gaung IN ('yes','no','na')),
    CONSTRAINT chk_eam_elb_tree CHECK (danger_tree IS NULL OR danger_tree IN ('yes','no','na')),
    CONSTRAINT chk_eam_elb_sign CHECK (safety_signage IS NULL OR safety_signage IN ('yes','no','na'))
);

-- UGC Cable conductor --------------------------------------------------------
CREATE TABLE IF NOT EXISTS eam_equipment_ugc_cable (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    equipment_id        UUID NOT NULL UNIQUE REFERENCES eam_equipment(id) ON DELETE CASCADE,
    cable_material      VARCHAR(12),
    cable_size_mm2      NUMERIC(12,2),
    current_rating_a    NUMERIC(12,2),
    cable_brand         VARCHAR(120),
    make_country        VARCHAR(120),
    CONSTRAINT chk_eam_ugc_mat CHECK (cable_material IS NULL OR cable_material IN ('copper','aluminium','xlpe','oil_filled','other'))
);

-- ============================================================================
-- Runtime role grants
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON
            eam_equipment, eam_component, eam_part,
            eam_equipment_transformer, eam_equipment_switchgear, eam_equipment_rmu,
            eam_equipment_protection, eam_equipment_scada, eam_equipment_battery,
            eam_equipment_feeder_pillar, eam_equipment_capacitor, eam_equipment_ner,
            eam_equipment_elb, eam_equipment_ugc_cable TO vortex_runtime';
    END IF;
END$$;

COMMENT ON TABLE eam_equipment IS
    'Central equipment asset (§3.2). One row per equipment item; category-specific nameplate/test data lives in a 1-1 eam_equipment_<category> detail table joined by equipment_id. Computed KPIs (health_index, mtbf, predictive) are derived on read, not stored.';
