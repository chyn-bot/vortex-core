-- Migration: SESB EAM field portal & API support (Phase 7)
--
-- Live field-agent location (§3.8 / §8 geolocation) — one current row per
-- user, upserted from the portal/device/API, plus job-derived positions.
-- The escalation job (§10.1) reuses existing eam_maintenance columns
-- (escalation_level, last_escalated_on) added in migration 005.

CREATE TABLE IF NOT EXISTS eam_field_agent_location (
    id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id         UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    agent_id        UUID         REFERENCES eam_field_agent(id) ON DELETE SET NULL,
    name            VARCHAR(160),
    lat             NUMERIC(10,6),
    lng             NUMERIC(10,6),
    accuracy_m      NUMERIC(10,2),
    speed_kmh       NUMERIC(8,2),
    heading         NUMERIC(6,2),
    battery_pct     INTEGER,
    status          VARCHAR(12)  NOT NULL DEFAULT 'available',
    source          VARCHAR(8)   NOT NULL DEFAULT 'device',
    maintenance_id  UUID         REFERENCES eam_maintenance(id) ON DELETE SET NULL,
    region_id       UUID         REFERENCES eam_region(id) ON DELETE SET NULL,
    last_seen       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    is_active       BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_loc_status CHECK (status IN ('available','en_route','on_site','off_duty')),
    CONSTRAINT chk_eam_loc_source CHECK (source IN ('device','portal','api','derived'))
);
-- One current location row per user (upsert target).
CREATE UNIQUE INDEX IF NOT EXISTS idx_eam_loc_user ON eam_field_agent_location (user_id);
CREATE INDEX IF NOT EXISTS idx_eam_loc_seen ON eam_field_agent_location (last_seen DESC);
DROP TRIGGER IF EXISTS trg_eam_loc_updated_at ON eam_field_agent_location;
CREATE TRIGGER trg_eam_loc_updated_at BEFORE UPDATE ON eam_field_agent_location FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- GPS coordinates on substations/towers feed job-derived positions & maps.
-- (Equipment inherits location from its substation; we read substation GPS.)
ALTER TABLE eam_substation ADD COLUMN IF NOT EXISTS latitude NUMERIC(10,6);
ALTER TABLE eam_substation ADD COLUMN IF NOT EXISTS longitude NUMERIC(10,6);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON eam_field_agent_location TO vortex_runtime';
    END IF;
END$$;
