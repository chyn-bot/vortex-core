-- Down migration for 009_eam_division_boundary.
-- Drops the derivation triggers + function, the columns this migration added
-- (leaving pre-existing division columns on region/equipment/vegetation), and
-- the DAMS/TAMS roles.

-- Triggers (all derived tables, incl. vegetation which pre-existed the column).
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'eam_zon','eam_kawasan','eam_site','eam_substation','eam_bay',
    'eam_component','eam_part',
    'eam_maintenance','eam_maintenance_plan','eam_defect','eam_inspection',
    'eam_condition_monitoring','eam_outage','eam_line_patrol','eam_field_agent',
    'eam_vegetation_section',
    'eam_transmission_line','eam_transmission_tower','eam_transmission_span',
    'eam_gantry','eam_ugc_line','eam_distribution_line','eam_cable_segment',
    'eam_equipment_transformer','eam_equipment_switchgear','eam_equipment_rmu',
    'eam_equipment_protection','eam_equipment_scada','eam_equipment_battery',
    'eam_equipment_feeder_pillar','eam_equipment_capacitor','eam_equipment_ner',
    'eam_equipment_elb','eam_equipment_ugc_cable'
  ]
  LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS trg_%I_division ON %I', t, t);
  END LOOP;
END$$;

DROP FUNCTION IF EXISTS eam_derive_division();

-- Columns this migration added (NOT region/equipment/vegetation).
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'eam_zon','eam_kawasan','eam_site','eam_substation','eam_bay',
    'eam_component','eam_part',
    'eam_maintenance','eam_maintenance_plan','eam_defect','eam_inspection',
    'eam_condition_monitoring','eam_outage','eam_line_patrol','eam_field_agent',
    'eam_transmission_line','eam_transmission_tower','eam_transmission_span',
    'eam_gantry','eam_ugc_line','eam_distribution_line','eam_cable_segment',
    'eam_equipment_transformer','eam_equipment_switchgear','eam_equipment_rmu',
    'eam_equipment_protection','eam_equipment_scada','eam_equipment_battery',
    'eam_equipment_feeder_pillar','eam_equipment_capacitor','eam_equipment_ner',
    'eam_equipment_elb','eam_equipment_ugc_cable'
  ]
  LOOP
    EXECUTE format('ALTER TABLE %I DROP CONSTRAINT IF EXISTS chk_%I_division', t, t);
    EXECUTE format('ALTER TABLE %I DROP COLUMN IF EXISTS division', t);
  END LOOP;
END$$;

DELETE FROM roles WHERE company_id IS NULL AND name IN ('EAM DAMS', 'EAM TAMS');
