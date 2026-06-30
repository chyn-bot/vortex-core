-- Migration: SESB EAM reference / seed data (§11)
--
-- Idempotent: each block seeds only when its table is empty, so it is
-- safe to re-run during tenant provisioning. Global rows (company_id
-- NULL) are visible to every tenant.

-- Voltage levels (≈12) --------------------------------------------------------
INSERT INTO eam_voltage_level (name, code, voltage_kv, voltage_type)
SELECT * FROM (VALUES
    ('240 V AC',  'AC240',  0.24,   'ac'),
    ('415 V AC',  'AC415',  0.415,  'ac'),
    ('11 kV',     'AC11',   11.0,   'ac'),
    ('33 kV',     'AC33',   33.0,   'ac'),
    ('66 kV',     'AC66',   66.0,   'ac'),
    ('132 kV',    'AC132',  132.0,  'ac'),
    ('275 kV',    'AC275',  275.0,  'ac'),
    ('500 kV',    'AC500',  500.0,  'ac'),
    ('24 Vdc',    'DC24',   0.024,  'dc'),
    ('30 Vdc',    'DC30',   0.030,  'dc'),
    ('48 Vdc',    'DC48',   0.048,  'dc'),
    ('110 Vdc',   'DC110',  0.110,  'dc')
) AS v(name, code, voltage_kv, voltage_type)
WHERE NOT EXISTS (SELECT 1 FROM eam_voltage_level);

-- Manufacturers (≈15) ---------------------------------------------------------
INSERT INTO eam_manufacturer (name, code)
SELECT * FROM (VALUES
    ('Siemens','SIE'), ('ABB','ABB'), ('Schneider Electric','SCH'), ('GE','GE'),
    ('Hitachi Energy','HIT'), ('Toshiba','TOS'), ('Eaton','EAT'), ('Ormazabal','ORM'),
    ('Lucy Electric','LUC'), ('MTM','MTM'), ('SEL','SEL'), ('Areva','ARE'),
    ('Exide','EXI'), ('Saft','SAF'), ('Hoppecke','HOP')
) AS m(name, code)
WHERE NOT EXISTS (SELECT 1 FROM eam_manufacturer);

-- Asset classes (≈25) — BRD §7.5 (Electrical) / §7.6 (Non-Electrical) ----------
INSERT INTO eam_asset_class (name, code, sequence, class_type, class_group)
SELECT * FROM (VALUES
    -- Substation types (Pencawang)
    ('PMU',                 'PMU',  10, 'electrical',     'pencawang'),
    ('PPU',                 'PPU',  11, 'electrical',     'pencawang'),
    ('SSU 33kV',            'SSU33',12, 'electrical',     'pencawang'),
    ('SSU 11kV',            'SSU11',13, 'electrical',     'pencawang'),
    ('PE',                  'PE',   14, 'electrical',     'pencawang'),
    -- Primary equipment
    ('Power Transformer',   'TX',   20, 'electrical',     'primary'),
    ('Switchgear',          'SWG',  21, 'electrical',     'primary'),
    ('Ring Main Unit',      'RMU',  22, 'electrical',     'primary'),
    ('Auto Recloser',       'AR',   23, 'electrical',     'primary'),
    ('Feeder Pillar',       'FP',   24, 'electrical',     'primary'),
    ('Capacitor Bank',      'CAP',  25, 'electrical',     'primary'),
    ('NER',                 'NER',  26, 'electrical',     'primary'),
    -- Secondary / auxiliary
    ('Protection Relay',    'PROT', 30, 'electrical',     'secondary'),
    ('SCADA / RTU',         'SCADA',31, 'electrical',     'secondary'),
    ('Battery Bank',        'BATT', 32, 'electrical',     'secondary'),
    ('Battery Charger',     'CHG',  33, 'electrical',     'secondary'),
    -- Transmission / UGC
    ('Transmission Tower',  'TWR',  40, 'electrical',     'primary'),
    ('Conductor',           'CND',  41, 'electrical',     'primary'),
    ('Underground Cable',   'UGC',  42, 'electrical',     'primary'),
    -- Non-electrical
    ('Building Exterior',   'BEXT', 50, 'non_electrical', 'building_exterior'),
    ('Building Interior',   'BINT', 51, 'non_electrical', 'building_interior'),
    ('Access Door',         'DOOR', 52, 'non_electrical', 'access_door'),
    ('Fire Safety',         'FIRE', 53, 'non_electrical', 'building_interior'),
    ('Earthing System',     'EARTH',54, 'electrical',     'secondary'),
    ('Lighting',            'LIGHT',55, 'non_electrical', 'building_interior')
) AS c(name, code, sequence, class_type, class_group)
WHERE NOT EXISTS (SELECT 1 FROM eam_asset_class);

-- Asset-type acronym registry — core MNEC codes ------------------------------
-- A representative spread across families; the full ≈128-code registry can be
-- bulk-imported from sesb_eam_data_model.json via the asset-type UI/importer.
INSERT INTO eam_asset_type (acronym, name, category, default_hierarchy_level, attribute_schema)
SELECT * FROM (VALUES
    -- structural
    ('SUB','Substation','primary_equipment',1,'generic'),
    ('BAY','Bay','primary_equipment',2,'generic'),
    ('TL','Transmission Line','primary_equipment',1,'generic'),
    ('TWR','Lattice Tower','tower_equipment',2,'tower_hardware'),
    ('SPAN','Span','tower_equipment',2,'tower_hardware'),
    ('GTRY','Gantry','primary_equipment',2,'generic'),
    -- primary equipment
    ('TX','Power Transformer','primary_equipment',3,'transformer'),
    ('OLTC','On-Load Tap Changer','primary_equipment',4,'transformer'),
    ('CB','Circuit Breaker','switchgear_type',3,'phase_primary'),
    ('GCB','Gas Circuit Breaker','switchgear_type',3,'phase_primary'),
    ('VCB','Vacuum Circuit Breaker','switchgear_type',3,'phase_primary'),
    ('GIS','Gas-Insulated Switchgear','switchgear_type',3,'phase_primary'),
    ('AIS','Air-Insulated Switchgear','switchgear_type',3,'phase_primary'),
    ('DS','Disconnect Switch','switchgear_type',3,'phase_primary'),
    ('ES','Earth Switch','switchgear_type',3,'phase_primary'),
    ('CT','Current Transformer','primary_equipment',3,'phase_primary'),
    ('VT','Voltage Transformer','primary_equipment',3,'phase_primary'),
    ('CVT','Capacitor Voltage Transformer','primary_equipment',3,'phase_primary'),
    ('LA','Lightning Arrester','primary_equipment',3,'phase_primary'),
    ('SA','Surge Arrester','primary_equipment',3,'phase_primary'),
    ('NER','Neutral Earthing Resistor','primary_equipment',3,'generic'),
    ('CAP','Capacitor Bank','primary_equipment',3,'generic'),
    ('RMU','Ring Main Unit','switchgear_type',3,'phase_primary'),
    ('FP','Feeder Pillar','primary_equipment',3,'generic'),
    -- tower hardware
    ('CND','Conductor','tower_equipment',3,'tower_hardware'),
    ('OPGW','Optical Ground Wire','tower_equipment',3,'tower_hardware'),
    ('INS','Insulator','tower_equipment',3,'tower_hardware'),
    ('JMP','Jumper','tower_equipment',3,'tower_hardware'),
    -- cable / UGC
    ('CBL','Cable','ugc_equipment',3,'ugc_accessory'),
    ('CSE','Cable Sealing End','ugc_equipment',3,'ugc_accessory'),
    ('ELB','Earth Link Box','ugc_equipment',3,'ugc_accessory'),
    -- control / automation
    ('RTU','Remote Terminal Unit','control_relay',3,'relay_control'),
    ('HMI','Human-Machine Interface','control_relay',3,'relay_control'),
    ('BCU','Bay Control Unit','control_relay',3,'relay_control'),
    ('PROT','Protection Relay','control_relay',3,'relay_control'),
    ('DIF','Differential Relay','control_relay',3,'relay_control'),
    ('DIS','Distance Relay','control_relay',3,'relay_control'),
    -- online monitoring
    ('DGA','DGA Monitor','online_monitoring',3,'generic'),
    ('TLA','Transformer Online Analyser','online_monitoring',3,'generic'),
    -- auxiliary
    ('BATT','Battery Bank','primary_equipment',3,'generic'),
    ('CHG','Battery Charger','primary_equipment',3,'generic')
) AS t(acronym, name, category, default_hierarchy_level, attribute_schema)
WHERE NOT EXISTS (SELECT 1 FROM eam_asset_type);

-- Geographic taxonomy — SESB regions/divisions -------------------------------
INSERT INTO eam_region (name, code, sequence, division)
SELECT * FROM (VALUES
    ('Pantai Barat (West Coast)', 'PB',  10, 'distribution'),
    ('Sandakan',                  'SDK', 20, 'distribution'),
    ('Tawau',                     'TWU', 30, 'distribution'),
    ('Transmission Division',     'TX',  40, 'transmission')
) AS r(name, code, sequence, division)
WHERE NOT EXISTS (SELECT 1 FROM eam_region);

-- Sample zones (one per distribution region) ----------------------------------
INSERT INTO eam_zon (name, code, sequence, region_id)
SELECT z.name, z.code, z.sequence, r.id
FROM (VALUES
    ('Kota Kinabalu',  'KK',  10, 'PB'),
    ('Papar',          'PPR', 20, 'PB'),
    ('Sandakan Zon',   'SDKZ',10, 'SDK'),
    ('Tawau Zon',      'TWUZ',10, 'TWU')
) AS z(name, code, sequence, region_code)
JOIN eam_region r ON r.code = z.region_code
WHERE NOT EXISTS (SELECT 1 FROM eam_zon);

-- Sample kawasans -------------------------------------------------------------
INSERT INTO eam_kawasan (name, code, sequence, zon_id, region_id)
SELECT k.name, k.code, k.sequence, z.id, z.region_id
FROM (VALUES
    ('Inanam',     'INM', 10, 'KK'),
    ('Likas',      'LKS', 20, 'KK'),
    ('Penampang',  'PNP', 10, 'PPR'),
    ('Sandakan Bandar','SDKB',10,'SDKZ'),
    ('Tawau Bandar','TWUB',10,'TWUZ')
) AS k(name, code, sequence, zon_code)
JOIN eam_zon z ON z.code = k.zon_code
WHERE NOT EXISTS (SELECT 1 FROM eam_kawasan);
