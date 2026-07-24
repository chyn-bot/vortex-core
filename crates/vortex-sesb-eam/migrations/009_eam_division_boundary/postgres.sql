-- ============================================================================
-- Migration 009: DAMS / TAMS division boundary (spec §6.1, §6.3)
--
-- Distribution (DAMS) and transmission (TAMS) are run by two teams that must
-- not see each other's assets or work. The boundary is a row-level control
-- keyed on a `division` attribute carried by every securable entity.
--
-- `division` is DERIVED, never typed in (§6.3):
--   * Linear assets get a CONSTANT (a mistagged region must not silently move
--     a whole set of linear assets across the boundary).
--   * Everything else inherits down the hierarchy / from its parent.
--
-- This migration:
--   1. adds a nullable `division` column (NULL = "unset", visible to both) to
--      every securable table that lacks one;
--   2. installs a single trigger function that derives it on INSERT/UPDATE so
--      no client can set it directly;
--   3. backfills existing rows;
--   4. seeds the orthogonal DAMS / TAMS roles.
--
-- `eam_region` (the root, where division is authored), `eam_equipment` (derived
-- in its handler) and `eam_vegetation_section` already carry the column; the
-- trigger re-derives equipment-dependent and vegetation rows for consistency.
-- ============================================================================

-- ── 1. Columns ──────────────────────────────────────────────────────────────
-- Nullable + CHECK. NULL is a first-class "unset" state (visible to both teams)
-- so an unclassified record is never silently lost.
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
    EXECUTE format('ALTER TABLE %I ADD COLUMN IF NOT EXISTS division VARCHAR(16)', t);
    EXECUTE format(
      'ALTER TABLE %I DROP CONSTRAINT IF EXISTS chk_%I_division', t, t);
    EXECUTE format(
      'ALTER TABLE %I ADD CONSTRAINT chk_%I_division '
      || 'CHECK (division IS NULL OR division IN (''transmission'',''distribution''))',
      t, t);
  END LOOP;
END$$;

-- Indexes: the boundary predicate (`division IN (...)`) is appended to every
-- list/search/dashboard query, so index it where rows are numerous.
CREATE INDEX IF NOT EXISTS idx_eam_maintenance_division  ON eam_maintenance(division);
CREATE INDEX IF NOT EXISTS idx_eam_defect_division        ON eam_defect(division);
CREATE INDEX IF NOT EXISTS idx_eam_inspection_division    ON eam_inspection(division);
CREATE INDEX IF NOT EXISTS idx_eam_condmon_division       ON eam_condition_monitoring(division);
CREATE INDEX IF NOT EXISTS idx_eam_substation_division    ON eam_substation(division);
CREATE INDEX IF NOT EXISTS idx_eam_bay_division           ON eam_bay(division);

-- ── 2. Derivation trigger ───────────────────────────────────────────────────
-- One function, dispatched on TG_TABLE_NAME. It ALWAYS overwrites NEW.division
-- from the record's parent (or a constant), so a client-supplied value is
-- ignored — "derived, never typed in". Linear assets are constants by design.
CREATE OR REPLACE FUNCTION eam_derive_division() RETURNS trigger AS $$
BEGIN
  IF TG_TABLE_NAME IN (
       'eam_transmission_line','eam_transmission_tower','eam_transmission_span',
       'eam_gantry','eam_ugc_line') THEN
    NEW.division := 'transmission';

  ELSIF TG_TABLE_NAME IN ('eam_distribution_line','eam_cable_segment') THEN
    NEW.division := 'distribution';

  -- Location hierarchy: inherit down from the region root.
  ELSIF TG_TABLE_NAME IN ('eam_zon','eam_kawasan','eam_site','eam_field_agent') THEN
    SELECT division INTO NEW.division FROM eam_region WHERE id = NEW.region_id;

  ELSIF TG_TABLE_NAME = 'eam_substation' THEN
    SELECT r.division INTO NEW.division
      FROM eam_site s JOIN eam_region r ON r.id = s.region_id
     WHERE s.id = NEW.site_id;

  ELSIF TG_TABLE_NAME = 'eam_bay' THEN
    SELECT division INTO NEW.division FROM eam_substation WHERE id = NEW.substation_id;

  ELSIF TG_TABLE_NAME = 'eam_outage' THEN
    SELECT division INTO NEW.division FROM eam_substation WHERE id = NEW.substation_id;

  -- Linear-op records: constant by whichever line they cover.
  ELSIF TG_TABLE_NAME IN ('eam_line_patrol','eam_vegetation_section') THEN
    NEW.division := CASE
      WHEN NEW.transmission_line_id IS NOT NULL THEN 'transmission'
      WHEN NEW.distribution_line_id IS NOT NULL THEN 'distribution'
      ELSE NULL END;

  -- Everything hanging off a piece of equipment (components, parts, work
  -- orders, plans, defects, inspections, readings, and the 1:1 detail rows).
  ELSE
    SELECT division INTO NEW.division FROM eam_equipment WHERE id = NEW.equipment_id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Attach the trigger to every table whose division is derived (i.e. all but
-- the authored root `eam_region` and handler-derived `eam_equipment`).
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
    EXECUTE format(
      'CREATE TRIGGER trg_%I_division BEFORE INSERT OR UPDATE ON %I '
      || 'FOR EACH ROW EXECUTE FUNCTION eam_derive_division()', t, t);
  END LOOP;
END$$;

-- ── 3. Backfill existing rows ───────────────────────────────────────────────
-- Order matters: hierarchy top-down first (so substation/bay resolve), then
-- everything that reads eam_equipment.division.
UPDATE eam_zon      z SET division = r.division FROM eam_region r WHERE r.id = z.region_id;
UPDATE eam_kawasan  k SET division = r.division FROM eam_region r WHERE r.id = k.region_id;
UPDATE eam_site     s SET division = r.division FROM eam_region r WHERE r.id = s.region_id;
UPDATE eam_field_agent a SET division = r.division FROM eam_region r WHERE r.id = a.region_id;
UPDATE eam_substation ss SET division = r.division
  FROM eam_site s JOIN eam_region r ON r.id = s.region_id WHERE s.id = ss.site_id;
UPDATE eam_bay      b SET division = ss.division FROM eam_substation ss WHERE ss.id = b.substation_id;
UPDATE eam_outage   o SET division = ss.division FROM eam_substation ss WHERE ss.id = o.substation_id;

-- Equipment: fill any NULLs from its bay's substation (handler sets it on new rows).
UPDATE eam_equipment e SET division = b.division
  FROM eam_bay b WHERE b.id = e.bay_id AND e.division IS NULL;

-- Linear assets: constants.
UPDATE eam_transmission_line  SET division = 'transmission';
UPDATE eam_transmission_tower SET division = 'transmission';
UPDATE eam_transmission_span  SET division = 'transmission';
UPDATE eam_gantry             SET division = 'transmission';
UPDATE eam_ugc_line           SET division = 'transmission';
UPDATE eam_distribution_line  SET division = 'distribution';
UPDATE eam_cable_segment      SET division = 'distribution';

-- Line-following ops: constant by line.
UPDATE eam_line_patrol SET division = CASE
  WHEN transmission_line_id IS NOT NULL THEN 'transmission'
  WHEN distribution_line_id IS NOT NULL THEN 'distribution' ELSE NULL END;
UPDATE eam_vegetation_section SET division = CASE
  WHEN transmission_line_id IS NOT NULL THEN 'transmission'
  WHEN distribution_line_id IS NOT NULL THEN 'distribution' ELSE division END;

-- Everything keyed by equipment_id.
UPDATE eam_component            c SET division = e.division FROM eam_equipment e WHERE e.id = c.equipment_id;
UPDATE eam_part                 p SET division = e.division FROM eam_equipment e WHERE e.id = p.equipment_id;
UPDATE eam_maintenance          m SET division = e.division FROM eam_equipment e WHERE e.id = m.equipment_id;
UPDATE eam_maintenance_plan     m SET division = e.division FROM eam_equipment e WHERE e.id = m.equipment_id;
UPDATE eam_defect               d SET division = e.division FROM eam_equipment e WHERE e.id = d.equipment_id;
UPDATE eam_inspection           i SET division = e.division FROM eam_equipment e WHERE e.id = i.equipment_id;
UPDATE eam_condition_monitoring c SET division = e.division FROM eam_equipment e WHERE e.id = c.equipment_id;

-- Equipment 1:1 detail rows keyed by equipment_id.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'eam_equipment_transformer','eam_equipment_switchgear','eam_equipment_rmu',
    'eam_equipment_protection','eam_equipment_scada','eam_equipment_battery',
    'eam_equipment_feeder_pillar','eam_equipment_capacitor','eam_equipment_ner',
    'eam_equipment_elb','eam_equipment_ugc_cable'
  ]
  LOOP
    EXECUTE format(
      'UPDATE %I d SET division = e.division FROM eam_equipment e '
      || 'WHERE e.id = d.equipment_id', t);
  END LOOP;
END$$;

-- ── 4. DAMS / TAMS roles (§6.1) ─────────────────────────────────────────────
-- Orthogonal to the operational ladder. They grant nothing on their own — they
-- only NARROW what a user may reach (enforced in the query layer, §6.3). They
-- must be independently assignable, so they are two separate roles, not a list.
INSERT INTO roles (id, company_id, name, description, permissions, is_system) VALUES
    ('5e5b0000-0000-0000-0000-0000000000a7', NULL, 'EAM DAMS',
     'Distribution asset team — confines the user to division = distribution',
     '[]', true),
    ('5e5b0000-0000-0000-0000-0000000000a8', NULL, 'EAM TAMS',
     'Transmission asset team — confines the user to division = transmission',
     '[]', true)
ON CONFLICT (company_id, name) DO NOTHING;

UPDATE roles SET owning_module = 'sesb_eam'
 WHERE company_id IS NULL AND name IN ('EAM DAMS', 'EAM TAMS');
