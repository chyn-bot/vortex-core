-- Stress Test: Insert 50,000 EAM Assets
-- Usage: psql -d <database> -f scripts/stress_test_50k_assets.sql
--
-- Creates the full hierarchy (sites → substations → bays) and reference data
-- (categories, manufacturers, unit types) if missing, then bulk-inserts
-- 50,000 assets with realistic Malaysian utility data.
--
-- Idempotent: skips if assets with 'STRESS-' prefix already exist.
-- Cleanup:    DELETE FROM eam_assets WHERE asset_code LIKE 'STRESS-%%';

BEGIN;

\echo '=== Vortex EAM Stress Test: 50,000 Assets ==='

DO $$
DECLARE
    v_company_id UUID;
    v_admin_id UUID;

    -- Reference data arrays
    v_site_ids UUID[];
    v_sub_ids UUID[];
    v_bay_ids UUID[];
    v_cat_ids UUID[];
    v_mfr_ids UUID[];
    v_unit_type_id UUID;

    -- Loop vars
    v_site_id UUID;
    v_sub_id UUID;
    v_i INTEGER;
    v_j INTEGER;
    v_batch_size INTEGER := 5000;
    v_total INTEGER := 50000;
    v_existing INTEGER;
    v_start_ts TIMESTAMPTZ;
    v_batch_ts TIMESTAMPTZ;

    -- Realistic Malaysian utility data
    v_eq_types TEXT[] := ARRAY[
        'Power Transformer', 'Distribution Transformer', 'Current Transformer',
        'Voltage Transformer', 'Circuit Breaker', 'Disconnect Switch',
        'Surge Arrester', 'Busbar Section', 'Cable Termination',
        'Capacitor Bank', 'Reactor', 'Battery Bank',
        'Ring Main Unit', 'Switchgear Panel', 'Protection Relay',
        'Metering Unit', 'SCADA RTU', 'Auto Recloser',
        'Load Break Switch', 'Fuse Unit'
    ];

    v_manufacturers TEXT[] := ARRAY[
        'ABB', 'Siemens', 'Schneider Electric', 'GE Grid Solutions',
        'Hitachi Energy', 'Toshiba', 'Hyundai Electric', 'Mitsubishi Electric',
        'Crompton Greaves', 'Fuji Electric', 'Eaton', 'Lucy Electric',
        'Ormazabal', 'Areva', 'TBEA', 'China XD Group'
    ];

    v_models TEXT[] := ARRAY[
        'T60', 'REL670', 'MiCOM P443', 'SEL-421', 'GRZ100',
        'PCS-9882', 'REB670', 'P543', 'MRA4', 'F650',
        'ZIV-ICM', 'KBCH-130', 'SafeRing', 'UniGear ZS1', 'RM6'
    ];

    v_statuses TEXT[] := ARRAY[
        'in_service', 'in_service', 'in_service', 'in_service', 'in_service',
        'in_service', 'in_service', 'standby', 'under_maintenance', 'faulty'
    ];

    v_cities TEXT[] := ARRAY[
        'Kuala Lumpur', 'Petaling Jaya', 'Shah Alam', 'Johor Bahru',
        'George Town', 'Ipoh', 'Kuching', 'Kota Kinabalu',
        'Melaka', 'Seremban', 'Kuantan', 'Kota Bharu',
        'Alor Setar', 'Miri', 'Sandakan', 'Taiping'
    ];

    v_states TEXT[] := ARRAY[
        'Kuala Lumpur', 'Selangor', 'Selangor', 'Johor',
        'Penang', 'Perak', 'Sarawak', 'Sabah',
        'Melaka', 'Negeri Sembilan', 'Pahang', 'Kelantan',
        'Kedah', 'Sarawak', 'Sabah', 'Perak'
    ];

    v_sub_types TEXT[] := ARRAY['indoor_gis', 'outdoor_ais', 'hybrid'];
    v_busbar_types TEXT[] := ARRAY['single', 'double', 'ring', 'breaker_and_half'];
    v_voltages TEXT[] := ARRAY['275kV', '132kV', '33kV', '11kV'];

    v_mfr_countries TEXT[] := ARRAY[
        'Switzerland', 'Germany', 'France', 'United States',
        'Switzerland', 'Japan', 'South Korea', 'Japan',
        'India', 'Japan', 'Ireland', 'United Kingdom',
        'Spain', 'France', 'China', 'China'
    ];

BEGIN
    v_start_ts := clock_timestamp();

    -- Check for existing stress test data
    SELECT COUNT(*) INTO v_existing FROM eam_assets WHERE asset_code LIKE 'STRESS-%%';
    IF v_existing > 0 THEN
        RAISE NOTICE 'Found % existing STRESS- assets. Skipping.', v_existing;
        RAISE NOTICE 'To re-run: DELETE FROM eam_assets WHERE asset_code LIKE ''STRESS-%%'';';
        RETURN;
    END IF;

    -- Get company
    SELECT id INTO v_company_id FROM companies WHERE active = true ORDER BY created_at LIMIT 1;
    IF v_company_id IS NULL THEN
        RAISE EXCEPTION 'No active company found. Run the application first to seed initial data.';
    END IF;

    -- Get admin user
    SELECT id INTO v_admin_id FROM users WHERE username = 'admin' LIMIT 1;

    RAISE NOTICE 'Company: %, Admin: %', v_company_id, v_admin_id;

    -- ================================================================
    -- 1. Ensure unit type exists (required for bays)
    -- ================================================================
    INSERT INTO eam_unit_types (company_id, code, name, description, is_active)
    VALUES (v_company_id, 'GEN', 'General Bay', 'General purpose bay type for stress test', true)
    ON CONFLICT (company_id, code) DO NOTHING;

    SELECT id INTO v_unit_type_id
    FROM eam_unit_types WHERE company_id = v_company_id AND code = 'GEN';

    -- ================================================================
    -- 2. Asset categories
    -- ================================================================
    INSERT INTO eam_asset_categories (company_id, code, name, description, is_active)
    VALUES
        (v_company_id, 'XFMR', 'Transformers', 'Power and distribution transformers', true),
        (v_company_id, 'SWGR', 'Switchgear', 'HV/MV/LV switchgear panels', true),
        (v_company_id, 'PROT', 'Protection', 'Protection relays and systems', true),
        (v_company_id, 'CBLG', 'Cabling', 'Power cables and terminations', true),
        (v_company_id, 'BATT', 'Batteries', 'Battery banks and chargers', true),
        (v_company_id, 'INST', 'Instruments', 'CTs, VTs, and metering', true),
        (v_company_id, 'CTRL', 'Control', 'SCADA, RTU, and control systems', true),
        (v_company_id, 'MISC', 'Miscellaneous', 'Other equipment', true)
    ON CONFLICT (company_id, code) DO NOTHING;

    SELECT array_agg(id ORDER BY code) INTO v_cat_ids
    FROM eam_asset_categories WHERE company_id = v_company_id AND is_active = true;

    -- ================================================================
    -- 3. Sites (16 substations across Malaysia)
    -- ================================================================
    FOR v_i IN 1..16 LOOP
        INSERT INTO eam_sites (company_id, code, name, city, state, country, site_type, status, is_active)
        VALUES (
            v_company_id,
            'SST-' || LPAD(v_i::text, 3, '0'),
            v_cities[v_i] || ' Main Intake',
            v_cities[v_i],
            v_states[v_i],
            'Malaysia',
            CASE WHEN v_i % 3 = 0 THEN 'Indoor GIS' WHEN v_i % 3 = 1 THEN 'Outdoor AIS' ELSE 'Hybrid' END,
            'active',
            true
        )
        ON CONFLICT (company_id, code) DO NOTHING;
    END LOOP;

    SELECT array_agg(id ORDER BY code) INTO v_site_ids
    FROM eam_sites WHERE company_id = v_company_id AND code LIKE 'SST-%' AND is_active = true;

    RAISE NOTICE 'Sites created: %', array_length(v_site_ids, 1);

    -- ================================================================
    -- 4. Substations (2 per site = 32 substations)
    -- ================================================================
    FOR v_i IN 1..array_length(v_site_ids, 1) LOOP
        FOR v_j IN 1..2 LOOP
            INSERT INTO eam_substations (
                company_id, site_id, code, name,
                substation_type, busbar_configuration, ownership,
                design_life_years, status, is_active
            ) VALUES (
                v_company_id,
                v_site_ids[v_i],
                'SUB-' || LPAD(v_i::text, 3, '0') || '-' || v_j,
                v_cities[v_i] || CASE WHEN v_j = 1 THEN ' Primary' ELSE ' Secondary' END || ' Substation',
                v_sub_types[1 + ((v_i + v_j) % 3)],
                v_busbar_types[1 + ((v_i + v_j) % 4)],
                'sesb',
                40,
                'active',
                true
            )
            ON CONFLICT (site_id, code) DO NOTHING;
        END LOOP;
    END LOOP;

    SELECT array_agg(id ORDER BY code) INTO v_sub_ids
    FROM eam_substations WHERE company_id = v_company_id AND code LIKE 'SUB-%' AND is_active = true;

    RAISE NOTICE 'Substations created: %', array_length(v_sub_ids, 1);

    -- ================================================================
    -- 5. Bays (8 per substation = 256 bays)
    -- ================================================================
    FOR v_i IN 1..array_length(v_sub_ids, 1) LOOP
        FOR v_j IN 1..8 LOOP
            INSERT INTO eam_bays (
                company_id, substation_id, unit_type_id,
                code, name, bay_type, is_active
            ) VALUES (
                v_company_id,
                v_sub_ids[v_i],
                v_unit_type_id,
                'BAY-' || LPAD(v_i::text, 3, '0') || '-' || LPAD(v_j::text, 2, '0'),
                CASE v_j
                    WHEN 1 THEN 'Incoming Line 1'
                    WHEN 2 THEN 'Incoming Line 2'
                    WHEN 3 THEN 'Bus Coupler'
                    WHEN 4 THEN 'Outgoing Feeder 1'
                    WHEN 5 THEN 'Outgoing Feeder 2'
                    WHEN 6 THEN 'Transformer Bay 1'
                    WHEN 7 THEN 'Transformer Bay 2'
                    ELSE 'Capacitor Bay'
                END,
                CASE
                    WHEN v_j <= 2 THEN 'feeder'
                    WHEN v_j = 3 THEN 'bus_coupler'
                    WHEN v_j <= 5 THEN 'feeder'
                    WHEN v_j <= 7 THEN 'transformer'
                    ELSE 'capacitor'
                END,
                true
            )
            ON CONFLICT DO NOTHING;
        END LOOP;
    END LOOP;

    SELECT array_agg(id ORDER BY code) INTO v_bay_ids
    FROM eam_bays WHERE company_id = v_company_id AND code LIKE 'BAY-%' AND is_active = true;

    RAISE NOTICE 'Bays created: %', array_length(v_bay_ids, 1);

    -- ================================================================
    -- 6. Manufacturers
    -- ================================================================
    FOR v_i IN 1..array_length(v_manufacturers, 1) LOOP
        INSERT INTO eam_manufacturers (company_id, code, name, country_name, is_active)
        VALUES (
            v_company_id,
            UPPER(LEFT(REPLACE(v_manufacturers[v_i], ' ', ''), 8)),
            v_manufacturers[v_i],
            v_mfr_countries[v_i],
            true
        )
        ON CONFLICT (company_id, code) DO NOTHING;
    END LOOP;

    SELECT array_agg(id ORDER BY name) INTO v_mfr_ids
    FROM eam_manufacturers WHERE company_id = v_company_id AND is_active = true;

    RAISE NOTICE 'Manufacturers: %', array_length(v_mfr_ids, 1);

    RAISE NOTICE 'Reference data ready: % categories, % sites, % substations, % bays, % manufacturers',
        array_length(v_cat_ids, 1),
        array_length(v_site_ids, 1),
        array_length(v_sub_ids, 1),
        array_length(v_bay_ids, 1),
        array_length(v_mfr_ids, 1);

    -- ================================================================
    -- 7. Bulk insert 50,000 assets in batches of 5,000
    -- ================================================================

    RAISE NOTICE 'Inserting % assets in batches of %...', v_total, v_batch_size;

    FOR v_i IN 0..((v_total - 1) / v_batch_size) LOOP
        v_batch_ts := clock_timestamp();

        INSERT INTO eam_assets (
            company_id, bay_id, category_id, manufacturer_id,
            asset_code, name, tag_number, description,
            manufacturer, model, serial_number,
            year_manufactured, commissioning_date, expected_life_years,
            purchase_cost, replacement_cost, criticality_rating,
            operational_status, condition_score,
            is_active, created_by
        )
        SELECT
            v_company_id,
            v_bay_ids[1 + (n % array_length(v_bay_ids, 1))],
            v_cat_ids[1 + (n % array_length(v_cat_ids, 1))],
            v_mfr_ids[1 + (n % array_length(v_mfr_ids, 1))],
            -- Unique asset code: STRESS-000001 .. STRESS-050000
            'STRESS-' || LPAD(n::text, 6, '0'),
            -- Name: "Power Transformer Kuala Lumpur #1234"
            v_eq_types[1 + (n % array_length(v_eq_types, 1))] || ' ' ||
                v_cities[1 + (n % array_length(v_cities, 1))] || ' #' || n,
            -- Tag
            'TAG-' || LPAD(n::text, 8, '0'),
            -- Description
            v_eq_types[1 + (n % array_length(v_eq_types, 1))] ||
                ' installed at ' || v_cities[1 + (n % array_length(v_cities, 1))] ||
                ' substation, bay ' || (1 + (n % 8)),
            -- Legacy manufacturer text
            v_manufacturers[1 + (n % array_length(v_manufacturers, 1))],
            -- Model
            v_models[1 + (n % array_length(v_models, 1))],
            -- Serial: SN-<md5 prefix>
            'SN-' || UPPER(SUBSTR(MD5(n::text), 1, 12)),
            -- Year manufactured: 2005-2025
            2005 + (n % 21),
            -- Commissioning date spread across 20 years
            ('2006-01-01'::date + ((n * 7) % 7300) * INTERVAL '1 day')::date,
            -- Expected life: 20-40 years
            20 + (n % 21),
            -- Purchase cost: RM 10,000 - RM 5,000,000
            10000.0 + (n % 4990) * 1000.0,
            -- Replacement cost: 1.3x purchase
            (10000.0 + (n % 4990) * 1000.0) * 1.3,
            -- Criticality weighted distribution
            CASE
                WHEN n % 100 < 5  THEN 5  --  5% very high
                WHEN n % 100 < 15 THEN 4  -- 10% high
                WHEN n % 100 < 45 THEN 3  -- 30% medium
                WHEN n % 100 < 80 THEN 2  -- 35% low-medium
                ELSE 1                     -- 20% low
            END,
            -- 70% in_service, 10% standby, 10% maintenance, 10% faulty
            v_statuses[1 + (n % array_length(v_statuses, 1))],
            -- Condition score: 40.0 - 100.0
            40.0 + (n % 61)::float,
            true,
            v_admin_id
        FROM generate_series(
            v_i * v_batch_size + 1,
            LEAST((v_i + 1) * v_batch_size, v_total)
        ) AS n;

        RAISE NOTICE '  Batch %/% done — % assets total (% ms)',
            v_i + 1,
            (v_total + v_batch_size - 1) / v_batch_size,
            LEAST((v_i + 1) * v_batch_size, v_total),
            EXTRACT(MILLISECONDS FROM clock_timestamp() - v_batch_ts)::int;
    END LOOP;

    -- ================================================================
    -- Summary
    -- ================================================================
    DECLARE
        v_c5 BIGINT; v_c4 BIGINT; v_c3 BIGINT; v_c2 BIGINT; v_c1 BIGINT;
        v_s_svc BIGINT; v_s_sby BIGINT; v_s_mnt BIGINT; v_s_flt BIGINT;
    BEGIN
        SELECT COUNT(*) INTO v_c5 FROM eam_assets WHERE asset_code LIKE 'STRESS-%%' AND criticality_rating = 5;
        SELECT COUNT(*) INTO v_c4 FROM eam_assets WHERE asset_code LIKE 'STRESS-%%' AND criticality_rating = 4;
        SELECT COUNT(*) INTO v_c3 FROM eam_assets WHERE asset_code LIKE 'STRESS-%%' AND criticality_rating = 3;
        SELECT COUNT(*) INTO v_c2 FROM eam_assets WHERE asset_code LIKE 'STRESS-%%' AND criticality_rating = 2;
        SELECT COUNT(*) INTO v_c1 FROM eam_assets WHERE asset_code LIKE 'STRESS-%%' AND criticality_rating = 1;
        SELECT COUNT(*) INTO v_s_svc FROM eam_assets WHERE asset_code LIKE 'STRESS-%%' AND operational_status = 'in_service';
        SELECT COUNT(*) INTO v_s_sby FROM eam_assets WHERE asset_code LIKE 'STRESS-%%' AND operational_status = 'standby';
        SELECT COUNT(*) INTO v_s_mnt FROM eam_assets WHERE asset_code LIKE 'STRESS-%%' AND operational_status = 'under_maintenance';
        SELECT COUNT(*) INTO v_s_flt FROM eam_assets WHERE asset_code LIKE 'STRESS-%%' AND operational_status = 'faulty';

        RAISE NOTICE '';
        RAISE NOTICE '============================================';
        RAISE NOTICE 'Inserted % assets in % seconds', v_total,
            ROUND(EXTRACT(EPOCH FROM clock_timestamp() - v_start_ts)::numeric, 2);
        RAISE NOTICE '============================================';
        RAISE NOTICE '';
        RAISE NOTICE 'Criticality distribution:';
        RAISE NOTICE '  5 (Very High): %', v_c5;
        RAISE NOTICE '  4 (High):      %', v_c4;
        RAISE NOTICE '  3 (Medium):    %', v_c3;
        RAISE NOTICE '  2 (Low-Med):   %', v_c2;
        RAISE NOTICE '  1 (Low):       %', v_c1;
        RAISE NOTICE '';
        RAISE NOTICE 'Status distribution:';
        RAISE NOTICE '  In Service:        %', v_s_svc;
        RAISE NOTICE '  Standby:           %', v_s_sby;
        RAISE NOTICE '  Under Maintenance: %', v_s_mnt;
        RAISE NOTICE '  Faulty:            %', v_s_flt;
    END;
END;
$$;

\echo ''
SELECT 'Total assets: ' || COUNT(*)::text FROM eam_assets;
SELECT 'Stress test assets: ' || COUNT(*)::text FROM eam_assets WHERE asset_code LIKE 'STRESS-%';
\echo ''
\echo 'To clean up:  DELETE FROM eam_assets WHERE asset_code LIKE ''STRESS-%'';'

COMMIT;
