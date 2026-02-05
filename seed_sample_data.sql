-- SESB EAM Sample Data Seed Script
-- This script inserts sample data for demonstration purposes
-- Run with: sudo -u postgres psql -d remicle -f seed_sample_data.sql

DO $$
DECLARE
    v_company_id UUID;
    v_user_id UUID;
    v_site_id UUID;
    v_fl_id UUID;
    v_category_tx_id UUID;
    v_category_sw_id UUID;
    v_category_bat_id UUID;
    v_category_ct_id UUID;
    v_category_sa_id UUID;
    v_voltage_132kv UUID;
    v_voltage_33kv UUID;
    v_voltage_11kv UUID;
    v_manufacturer_id UUID;
    v_asset_tx1_id UUID;
    v_asset_tx2_id UUID;
    v_asset_sw1_id UUID;
    v_asset_sw2_id UUID;
    v_asset_bat1_id UUID;
    v_asset_ct1_id UUID;
    v_asset_sa1_id UUID;
BEGIN
    -- Get company and user
    SELECT id INTO v_company_id FROM companies LIMIT 1;
    SELECT id INTO v_user_id FROM users WHERE company_id = v_company_id LIMIT 1;

    IF v_company_id IS NULL THEN
        RAISE EXCEPTION 'No company found';
    END IF;

    -- Get voltage levels
    SELECT id INTO v_voltage_132kv FROM eam_voltage_levels WHERE name = '132 kV' LIMIT 1;
    SELECT id INTO v_voltage_33kv FROM eam_voltage_levels WHERE name = '33 kV' LIMIT 1;
    SELECT id INTO v_voltage_11kv FROM eam_voltage_levels WHERE name = '11 kV' LIMIT 1;

    -- Get asset categories
    SELECT id INTO v_category_tx_id FROM eam_asset_categories WHERE name = 'Transformer' AND company_id = v_company_id LIMIT 1;
    SELECT id INTO v_category_sw_id FROM eam_asset_categories WHERE name = 'Switch Gear' AND company_id = v_company_id LIMIT 1;
    SELECT id INTO v_category_bat_id FROM eam_asset_categories WHERE name ILIKE '%Battery%' AND company_id = v_company_id LIMIT 1;

    -- If category not found, get first one
    IF v_category_tx_id IS NULL THEN
        SELECT id INTO v_category_tx_id FROM eam_asset_categories WHERE company_id = v_company_id LIMIT 1;
    END IF;
    IF v_category_sw_id IS NULL THEN
        v_category_sw_id := v_category_tx_id;
    END IF;
    IF v_category_bat_id IS NULL THEN
        v_category_bat_id := v_category_tx_id;
    END IF;
    v_category_ct_id := v_category_tx_id;
    v_category_sa_id := v_category_tx_id;

    RAISE NOTICE 'Company: %, User: %', v_company_id, v_user_id;
    RAISE NOTICE 'Voltage levels: 132kV=%, 33kV=%, 11kV=%', v_voltage_132kv, v_voltage_33kv, v_voltage_11kv;

    -- =========================================================================
    -- MANUFACTURERS
    -- =========================================================================
    INSERT INTO eam_manufacturers (id, company_id, code, name, country_code, country_name, website, is_approved_vendor, is_active, created_by, updated_by)
    VALUES
        (gen_random_uuid(), v_company_id, 'ABB', 'ABB Ltd', 'CH', 'Switzerland', 'https://www.abb.com', true, true, v_user_id, v_user_id),
        (gen_random_uuid(), v_company_id, 'SIEMENS', 'Siemens AG', 'DE', 'Germany', 'https://www.siemens.com', true, true, v_user_id, v_user_id),
        (gen_random_uuid(), v_company_id, 'SCHNEIDER', 'Schneider Electric', 'FR', 'France', 'https://www.se.com', true, true, v_user_id, v_user_id),
        (gen_random_uuid(), v_company_id, 'GE', 'General Electric', 'US', 'United States', 'https://www.ge.com', true, true, v_user_id, v_user_id),
        (gen_random_uuid(), v_company_id, 'HITACHI', 'Hitachi Energy', 'JP', 'Japan', 'https://www.hitachienergy.com', true, true, v_user_id, v_user_id),
        (gen_random_uuid(), v_company_id, 'TOSHIBA', 'Toshiba Corporation', 'JP', 'Japan', 'https://www.toshiba.com', false, true, v_user_id, v_user_id)
    ON CONFLICT (company_id, code) DO NOTHING;

    SELECT id INTO v_manufacturer_id FROM eam_manufacturers WHERE code = 'ABB' AND company_id = v_company_id;

    -- =========================================================================
    -- SITES
    -- =========================================================================
    INSERT INTO eam_sites (id, company_id, code, name, site_type, city, state, status, is_active, created_by, updated_by)
    VALUES
        (gen_random_uuid(), v_company_id, 'PMU-KL01', 'Kuala Lumpur Main Intake', 'PMU', 'Kuala Lumpur', 'Wilayah Persekutuan', 'active', true, v_user_id, v_user_id),
        (gen_random_uuid(), v_company_id, 'PPU-PJ01', 'Petaling Jaya Substation', 'PPU', 'Petaling Jaya', 'Selangor', 'active', true, v_user_id, v_user_id),
        (gen_random_uuid(), v_company_id, 'SSU-SBN01', 'Subang Main Switching', 'SSU', 'Subang Jaya', 'Selangor', 'active', true, v_user_id, v_user_id)
    ON CONFLICT (company_id, code) DO NOTHING;

    SELECT id INTO v_site_id FROM eam_sites WHERE code = 'PMU-KL01' AND company_id = v_company_id;

    -- =========================================================================
    -- FUNCTIONAL LOCATIONS - Use existing one
    -- =========================================================================
    SELECT id INTO v_fl_id FROM eam_functional_locations WHERE company_id = v_company_id LIMIT 1;

    -- =========================================================================
    -- ASSETS - Create parent asset records first
    -- =========================================================================
    -- Transformer Assets
    v_asset_tx1_id := gen_random_uuid();
    v_asset_tx2_id := gen_random_uuid();
    INSERT INTO eam_assets (id, company_id, functional_location_id, category_id, voltage_level_id, manufacturer_id,
        asset_code, name, tag_number, description, manufacturer, model, serial_number, year_manufactured,
        commissioning_date, criticality_rating, operational_status, is_active, created_by, updated_by)
    VALUES
        (v_asset_tx1_id, v_company_id, v_fl_id, v_category_tx_id, v_voltage_132kv, v_manufacturer_id,
         'TX-PMU-KL01-001', 'Main Power Transformer 1', 'TX001', '132/33kV Main Power Transformer',
         'ABB', 'TRFM-60MVA', 'ABB-2019-TX-0042', 2019, '2019-06-15', 5, 'in_service', true, v_user_id, v_user_id),
        (v_asset_tx2_id, v_company_id, v_fl_id, v_category_tx_id, v_voltage_132kv, v_manufacturer_id,
         'TX-PMU-KL01-002', 'Main Power Transformer 2', 'TX002', '132/33kV Backup Transformer',
         'ABB', 'TRFM-60MVA', 'ABB-2020-TX-0088', 2020, '2020-03-20', 5, 'in_service', true, v_user_id, v_user_id)
    ON CONFLICT (asset_code) DO NOTHING;

    -- Switchgear Assets
    v_asset_sw1_id := gen_random_uuid();
    v_asset_sw2_id := gen_random_uuid();
    INSERT INTO eam_assets (id, company_id, functional_location_id, category_id, voltage_level_id, manufacturer_id,
        asset_code, name, tag_number, description, manufacturer, model, serial_number, year_manufactured,
        criticality_rating, operational_status, is_active, created_by, updated_by)
    VALUES
        (v_asset_sw1_id, v_company_id, v_fl_id, v_category_sw_id, v_voltage_33kv, v_manufacturer_id,
         'SW-PMU-KL01-001', '33kV Switchgear Panel A', 'SW001', '33kV Indoor SF6 Switchgear',
         'Siemens', 'NXPLUS', 'SIE-2020-SW-1234', 2020, 4, 'in_service', true, v_user_id, v_user_id),
        (v_asset_sw2_id, v_company_id, v_fl_id, v_category_sw_id, v_voltage_33kv, v_manufacturer_id,
         'SW-PMU-KL01-002', '33kV Switchgear Panel B', 'SW002', '33kV Indoor SF6 Switchgear',
         'Siemens', 'NXPLUS', 'SIE-2020-SW-1235', 2020, 4, 'in_service', true, v_user_id, v_user_id)
    ON CONFLICT (asset_code) DO NOTHING;

    -- Battery Assets
    v_asset_bat1_id := gen_random_uuid();
    INSERT INTO eam_assets (id, company_id, functional_location_id, category_id, manufacturer_id,
        asset_code, name, tag_number, description, manufacturer, model, serial_number, year_manufactured,
        criticality_rating, operational_status, is_active, created_by, updated_by)
    VALUES
        (v_asset_bat1_id, v_company_id, v_fl_id, v_category_bat_id, v_manufacturer_id,
         'BAT-PMU-KL01-001', 'DC Battery Bank A', 'BAT001', 'DC Supply Battery System 110V',
         'Exide', 'POWERFIT-S500', 'EXI-2021-BAT-001', 2021, 3, 'in_service', true, v_user_id, v_user_id)
    ON CONFLICT (asset_code) DO NOTHING;

    -- CT/VT Asset
    v_asset_ct1_id := gen_random_uuid();
    INSERT INTO eam_assets (id, company_id, functional_location_id, category_id, voltage_level_id, manufacturer_id,
        asset_code, name, tag_number, description, manufacturer, model, serial_number, year_manufactured,
        criticality_rating, operational_status, is_active, created_by, updated_by)
    VALUES
        (v_asset_ct1_id, v_company_id, v_fl_id, v_category_ct_id, v_voltage_132kv, v_manufacturer_id,
         'CT-PMU-KL01-001', '132kV Current Transformer', 'CT001', 'HV Current Transformer',
         'ABB', 'IMB-145', 'ABB-CT-2020-001', 2020, 3, 'in_service', true, v_user_id, v_user_id)
    ON CONFLICT (asset_code) DO NOTHING;

    -- Surge Arrester Asset
    v_asset_sa1_id := gen_random_uuid();
    INSERT INTO eam_assets (id, company_id, functional_location_id, category_id, voltage_level_id, manufacturer_id,
        asset_code, name, tag_number, description, manufacturer, model, serial_number, year_manufactured,
        criticality_rating, operational_status, is_active, created_by, updated_by)
    VALUES
        (v_asset_sa1_id, v_company_id, v_fl_id, v_category_sa_id, v_voltage_132kv, v_manufacturer_id,
         'SA-PMU-KL01-001', '132kV Surge Arrester A', 'SA001', 'Metal Oxide Surge Arrester',
         'ABB', 'EXLIM-T', 'ABB-SA-2019-001', 2019, 3, 'in_service', true, v_user_id, v_user_id)
    ON CONFLICT (asset_code) DO NOTHING;

    -- Get actual IDs if assets already existed
    SELECT id INTO v_asset_tx1_id FROM eam_assets WHERE asset_code = 'TX-PMU-KL01-001';
    SELECT id INTO v_asset_tx2_id FROM eam_assets WHERE asset_code = 'TX-PMU-KL01-002';
    SELECT id INTO v_asset_sw1_id FROM eam_assets WHERE asset_code = 'SW-PMU-KL01-001';
    SELECT id INTO v_asset_sw2_id FROM eam_assets WHERE asset_code = 'SW-PMU-KL01-002';
    SELECT id INTO v_asset_bat1_id FROM eam_assets WHERE asset_code = 'BAT-PMU-KL01-001';
    SELECT id INTO v_asset_ct1_id FROM eam_assets WHERE asset_code = 'CT-PMU-KL01-001';
    SELECT id INTO v_asset_sa1_id FROM eam_assets WHERE asset_code = 'SA-PMU-KL01-001';

    RAISE NOTICE 'Assets created: TX1=%, TX2=%, SW1=%', v_asset_tx1_id, v_asset_tx2_id, v_asset_sw1_id;

    -- =========================================================================
    -- EQUIPMENT - TRANSFORMERS (linked to assets)
    -- =========================================================================
    INSERT INTO eam_transformers (id, asset_id, transformer_type, mva_rating, primary_voltage, secondary_voltage,
        vector_group, number_of_windings, phases, cooling_type, oil_type, oil_volume_liters,
        impedance_percent, winding_material, has_buchholz_relay, has_pressure_relief, has_wti, has_oti, has_mog, dga_status)
    VALUES
        (gen_random_uuid(), v_asset_tx1_id, 'power', 60.0, 132.0, 33.0, 'YNd11', 2, 3, 'ONAN/ONAF', 'Mineral', 25000,
         12.5, 'copper', true, true, true, true, true, 'normal'),
        (gen_random_uuid(), v_asset_tx2_id, 'power', 60.0, 132.0, 33.0, 'YNd11', 2, 3, 'ONAN/ONAF', 'Mineral', 25000,
         12.5, 'copper', true, true, true, true, true, 'normal')
    ON CONFLICT (asset_id) DO NOTHING;

    -- =========================================================================
    -- EQUIPMENT - SWITCHGEAR (linked to assets)
    -- =========================================================================
    INSERT INTO eam_switch_gears (id, asset_id, switchgear_type, breaker_type, rated_voltage, rated_current,
        rated_short_circuit_current, sf6_volume_kg, control_voltage_vdc, motor_voltage_vac,
        mechanism_type, number_of_poles, position)
    VALUES
        (gen_random_uuid(), v_asset_sw1_id, 'indoor', 'SF6', 33.0, 1250, 25.0, 15.5, 110, 415, 'motor', 3, 'closed'),
        (gen_random_uuid(), v_asset_sw2_id, 'indoor', 'SF6', 33.0, 1250, 25.0, 15.5, 110, 415, 'motor', 3, 'open')
    ON CONFLICT (asset_id) DO NOTHING;

    -- =========================================================================
    -- EQUIPMENT - BATTERIES (linked to assets)
    -- =========================================================================
    INSERT INTO eam_batteries (id, asset_id, battery_type, battery_application, nominal_voltage, capacity_ah,
        number_of_cells, cells_per_string, number_of_strings, charger_manufacturer, charger_model,
        state_of_health, state_of_charge, current_mode)
    VALUES
        (gen_random_uuid(), v_asset_bat1_id, 'lead_acid', 'substation_dc', 110.0, 200.0, 55, 55, 1,
         'Chloride', 'SLC-50A', 95.5, 100.0, 'float')
    ON CONFLICT (asset_id) DO NOTHING;

    -- =========================================================================
    -- EQUIPMENT - CT/VT (linked to assets)
    -- =========================================================================
    INSERT INTO eam_current_voltage_transformers (id, asset_id, device_type, ratio_primary, ratio_secondary,
        accuracy_class, burden_va, rated_voltage_kv, number_of_cores)
    VALUES
        (gen_random_uuid(), v_asset_ct1_id, 'CT', 600.0, 1.0, '0.2', 30.0, 132.0, 3)
    ON CONFLICT (asset_id) DO NOTHING;

    -- =========================================================================
    -- EQUIPMENT - SURGE ARRESTERS (linked to assets)
    -- =========================================================================
    INSERT INTO eam_surge_arresters (id, asset_id, arrester_type, mcov_kv, rated_voltage_kv,
        discharge_class, nominal_discharge_current_ka, housing_material, has_surge_counter)
    VALUES
        (gen_random_uuid(), v_asset_sa1_id, 'metal_oxide', 106.0, 132.0, '3', 10.0, 'silicone', true)
    ON CONFLICT (asset_id) DO NOTHING;

    -- =========================================================================
    -- WORK ORDERS
    -- =========================================================================
    INSERT INTO eam_work_orders (id, company_id, asset_id, wo_number, title, description,
        maintenance_type, priority, state, scheduled_start, scheduled_end, created_by)
    VALUES
        (gen_random_uuid(), v_company_id, v_asset_tx1_id, 'WO-2026-00001', 'Annual Transformer Inspection',
         'Perform annual visual inspection and oil sampling for TX-PMU-KL01-001', 'inspection', 2, 'scheduled',
         '2026-02-15 08:00:00+08', '2026-02-15 17:00:00+08', v_user_id),
        (gen_random_uuid(), v_company_id, v_asset_tx1_id, 'WO-2026-00002', 'DGA Oil Sampling - Q1',
         'Quarterly dissolved gas analysis sampling for all power transformers', 'testing', 1, 'in_progress',
         '2026-02-01 08:00:00+08', '2026-02-07 17:00:00+08', v_user_id),
        (gen_random_uuid(), v_company_id, v_asset_sw1_id, 'WO-2026-00003', 'Switchgear Contact Maintenance',
         'Inspect and clean switchgear contacts, check SF6 pressure', 'pm', 2, 'draft',
         '2026-03-01 08:00:00+08', '2026-03-02 17:00:00+08', v_user_id),
        (gen_random_uuid(), v_company_id, v_asset_bat1_id, 'WO-2026-00004', 'Battery Capacity Test',
         'Annual battery discharge test and cell balancing', 'testing', 3, 'scheduled',
         '2026-02-20 08:00:00+08', '2026-02-21 17:00:00+08', v_user_id),
        (gen_random_uuid(), v_company_id, v_asset_tx1_id, 'WO-2026-00005', 'Emergency Repair - Oil Leak',
         'Repair minor oil leak detected on transformer radiator', 'emergency', 0, 'on_hold',
         '2026-02-03 08:00:00+08', '2026-02-04 17:00:00+08', v_user_id),
        (gen_random_uuid(), v_company_id, v_asset_sw2_id, 'WO-2025-00089', 'Thermal Imaging Survey',
         'Completed thermal scan of all HV connections', 'inspection', 2, 'completed',
         '2026-01-15 08:00:00+08', '2026-01-15 17:00:00+08', v_user_id)
    ON CONFLICT (wo_number) DO NOTHING;

    -- =========================================================================
    -- DGA ANALYSES
    -- =========================================================================
    INSERT INTO eam_dga_analyses (id, asset_id, sample_date, lab_reference,
        hydrogen_h2_ppm, methane_ch4_ppm, ethane_c2h6_ppm, ethylene_c2h4_ppm, acetylene_c2h2_ppm,
        carbon_monoxide_co_ppm, carbon_dioxide_co2_ppm, oxygen_o2_ppm, nitrogen_n2_ppm,
        total_combustible_gas_ppm, fault_type, status, assessment_method, created_by)
    VALUES
        (gen_random_uuid(), v_asset_tx1_id, '2026-01-15 10:00:00+08', 'LAB-2026-0042',
         45, 25, 12, 8, 0.5, 350, 2800, 18000, 52000, 440.5, NULL, 'normal', 'IEEE C57.104', v_user_id),
        (gen_random_uuid(), v_asset_tx1_id, '2025-10-12 10:00:00+08', 'LAB-2025-0389',
         38, 22, 10, 6, 0.2, 320, 2650, 19000, 53000, 396.2, NULL, 'normal', 'IEEE C57.104', v_user_id),
        (gen_random_uuid(), v_asset_tx1_id, '2025-07-20 10:00:00+08', 'LAB-2025-0267',
         85, 45, 28, 35, 2.5, 480, 3200, 16500, 51000, 676.0, 'thermal_low', 'caution', 'IEEE C57.104', v_user_id),
        (gen_random_uuid(), v_asset_tx2_id, '2026-01-20 10:00:00+08', 'LAB-2026-0051',
         32, 18, 8, 5, 0.1, 290, 2500, 20000, 54000, 353.1, NULL, 'normal', 'IEEE C57.104', v_user_id)
    ON CONFLICT DO NOTHING;

    -- =========================================================================
    -- OIL QUALITY TESTS
    -- =========================================================================
    INSERT INTO eam_oil_quality_tests (id, asset_id, test_date, lab_reference,
        bdv_kv, moisture_ppm, acidity_mg_koh, ift_mn_m, tan_delta, color, furan_2fal_ppb, status, created_by)
    VALUES
        (gen_random_uuid(), v_asset_tx1_id, '2026-01-15 10:00:00+08', 'OIL-2026-0042',
         72.5, 8.2, 0.015, 42.0, 0.002, 1.0, 120, 'good', v_user_id),
        (gen_random_uuid(), v_asset_tx1_id, '2025-07-20 10:00:00+08', 'OIL-2025-0267',
         68.0, 12.5, 0.022, 38.5, 0.004, 1.5, 180, 'fair', v_user_id),
        (gen_random_uuid(), v_asset_tx2_id, '2026-01-20 10:00:00+08', 'OIL-2026-0051',
         75.0, 6.5, 0.012, 45.0, 0.001, 0.5, 80, 'good', v_user_id)
    ON CONFLICT DO NOTHING;

    -- =========================================================================
    -- THERMAL IMAGING
    -- =========================================================================
    INSERT INTO eam_thermal_imaging (id, asset_id, scan_date, component_location,
        ambient_temp_c, load_percent, max_temp_c, reference_temp_c, hot_spot_location,
        delta_t_c, severity, recommended_action, created_by)
    VALUES
        (gen_random_uuid(), v_asset_tx1_id, '2026-01-15 14:00:00+08', 'HV Bushing',
         32.0, 75.0, 45.5, 35.0, 'HV bushing connection', 10.5, 'normal', 'Continue monitoring', v_user_id),
        (gen_random_uuid(), v_asset_sw1_id, '2026-01-15 14:30:00+08', 'Cable Termination',
         31.0, 80.0, 68.2, 38.0, 'Cable termination - Phase R', 30.2, 'serious', 'Schedule maintenance within 2 weeks', v_user_id),
        (gen_random_uuid(), v_asset_ct1_id, '2026-01-15 15:00:00+08', 'Primary Terminal',
         31.5, 70.0, 42.0, 33.0, 'Primary terminal connection', 9.0, 'normal', 'Continue monitoring', v_user_id)
    ON CONFLICT DO NOTHING;

    RAISE NOTICE 'Sample data seeded successfully for company %', v_company_id;
END $$;

-- Show counts
SELECT 'Manufacturers' as entity, COUNT(*) as count FROM eam_manufacturers WHERE is_active = true
UNION ALL
SELECT 'Sites', COUNT(*) FROM eam_sites WHERE is_active = true
UNION ALL
SELECT 'Assets', COUNT(*) FROM eam_assets WHERE is_active = true
UNION ALL
SELECT 'Transformers', COUNT(*) FROM eam_transformers
UNION ALL
SELECT 'Switchgear', COUNT(*) FROM eam_switch_gears
UNION ALL
SELECT 'Batteries', COUNT(*) FROM eam_batteries
UNION ALL
SELECT 'CT/VT', COUNT(*) FROM eam_current_voltage_transformers
UNION ALL
SELECT 'Surge Arresters', COUNT(*) FROM eam_surge_arresters
UNION ALL
SELECT 'Work Orders', COUNT(*) FROM eam_work_orders
UNION ALL
SELECT 'DGA Analyses', COUNT(*) FROM eam_dga_analyses
UNION ALL
SELECT 'Oil Quality Tests', COUNT(*) FROM eam_oil_quality_tests
UNION ALL
SELECT 'Thermal Imaging', COUNT(*) FROM eam_thermal_imaging;
