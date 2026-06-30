-- Migration: SESB EAM planning & governance (Phase 5)
--
-- Maintenance plans + frequency control (§5.3), workforce / field agents
-- (§3.8), the approval framework (§3.10) and the six security roles (§6).
-- Also wires the deferred plan_id / field_agent_group_id FKs that Phase 4
-- left as plain UUIDs on eam_maintenance.

-- ============================================================================
-- Maintenance plan (§3.6 / §5.3) — recurring schedule + frequency control
-- ============================================================================
CREATE TABLE IF NOT EXISTS eam_maintenance_plan (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                VARCHAR(64),
    description         VARCHAR(300),
    equipment_id        UUID         NOT NULL REFERENCES eam_equipment(id) ON DELETE CASCADE,
    equipment_category  VARCHAR(24),
    substation_id       UUID         REFERENCES eam_substation(id) ON DELETE SET NULL,
    site_id             UUID         REFERENCES eam_site(id) ON DELETE SET NULL,
    region_id           UUID         REFERENCES eam_region(id) ON DELETE SET NULL,
    kawasan_id          UUID         REFERENCES eam_kawasan(id) ON DELETE SET NULL,
    asset_class_id      UUID         REFERENCES eam_asset_class(id) ON DELETE SET NULL,
    maintenance_type    VARCHAR(12)  NOT NULL DEFAULT 'pm',
    priority            VARCHAR(2)   NOT NULL DEFAULT '1',
    risk_tier           VARCHAR(8),
    procedure_reference VARCHAR(120),
    procedure_url       VARCHAR(400),
    planned_duration_hours NUMERIC(8,2),
    assigned_to         UUID         REFERENCES users(id),
    checklist_template_id UUID       REFERENCES eam_checklist_template(id) ON DELETE SET NULL,
    start_date          DATE         NOT NULL DEFAULT CURRENT_DATE,
    next_maintenance_date DATE       NOT NULL DEFAULT CURRENT_DATE,
    frequency_interval  INTEGER      NOT NULL DEFAULT 1,
    frequency_unit      VARCHAR(8)   NOT NULL DEFAULT 'month',
    planning_horizon_interval INTEGER NOT NULL DEFAULT 1,
    planning_horizon_unit VARCHAR(8) NOT NULL DEFAULT 'year',
    -- frequency-change control (§5.3, admin-only)
    frequency_unlocked  BOOLEAN      NOT NULL DEFAULT FALSE,
    frequency_change_reason TEXT,
    frequency_change_approved_by UUID REFERENCES users(id),
    frequency_change_approved_date TIMESTAMPTZ,
    frequency_change_count INTEGER   NOT NULL DEFAULT 0,
    state               VARCHAR(12)  NOT NULL DEFAULT 'draft',
    last_generated_date DATE,
    notes               TEXT,
    active              BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id          UUID         REFERENCES companies(id),
    created_by          UUID         REFERENCES users(id),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_plan_type CHECK (maintenance_type IN ('pm','cm','inspection','testing','overhaul')),
    CONSTRAINT chk_eam_plan_priority CHECK (priority IN ('0','1','2','3')),
    CONSTRAINT chk_eam_plan_tier CHECK (risk_tier IS NULL OR risk_tier IN ('tier_1','tier_2','tier_3')),
    CONSTRAINT chk_eam_plan_funit CHECK (frequency_unit IN ('day','week','month','year')),
    CONSTRAINT chk_eam_plan_hunit CHECK (planning_horizon_unit IN ('day','week','month','year')),
    CONSTRAINT chk_eam_plan_state CHECK (state IN ('draft','active','done','cancelled'))
);
CREATE INDEX IF NOT EXISTS idx_eam_plan_equip ON eam_maintenance_plan (equipment_id);
CREATE INDEX IF NOT EXISTS idx_eam_plan_next  ON eam_maintenance_plan (next_maintenance_date);
CREATE INDEX IF NOT EXISTS idx_eam_plan_state ON eam_maintenance_plan (state);
DROP TRIGGER IF EXISTS trg_eam_plan_updated_at ON eam_maintenance_plan;
CREATE TRIGGER trg_eam_plan_updated_at BEFORE UPDATE ON eam_maintenance_plan FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- Workforce / field agents (§3.8)
-- ============================================================================
CREATE TABLE IF NOT EXISTS eam_field_agent_group (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                VARCHAR(160) NOT NULL,
    code                VARCHAR(40)  NOT NULL,
    sequence            INTEGER      NOT NULL DEFAULT 0,
    group_type          VARCHAR(8)   NOT NULL DEFAULT 'crew',
    supervisor_user_id  UUID         REFERENCES users(id),
    skill_category      VARCHAR(24),
    description         TEXT,
    active              BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id          UUID         REFERENCES companies(id),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_fag_type CHECK (group_type IN ('area','skill','crew'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_eam_fag_code ON eam_field_agent_group (code);
DROP TRIGGER IF EXISTS trg_eam_fag_updated_at ON eam_field_agent_group;
CREATE TRIGGER trg_eam_fag_updated_at BEFORE UPDATE ON eam_field_agent_group FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TABLE IF NOT EXISTS eam_field_agent (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                VARCHAR(160) NOT NULL,
    employee_no         VARCHAR(40),
    user_id             UUID         REFERENCES users(id),
    agent_level         VARCHAR(12),
    is_supervisor       BOOLEAN      NOT NULL DEFAULT FALSE,
    skill_category      VARCHAR(24),
    region_id           UUID         REFERENCES eam_region(id) ON DELETE SET NULL,
    supervisor_group_id UUID         REFERENCES eam_field_agent_group(id) ON DELETE SET NULL,
    phone               VARCHAR(40),
    emergency_contact   VARCHAR(160),
    max_concurrent_jobs INTEGER,
    notes               TEXT,
    active              BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id          UUID         REFERENCES companies(id),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_agent_level CHECK (agent_level IS NULL OR agent_level IN ('tukang','juruteknik','jurutera','supervisor','manager'))
);
CREATE INDEX IF NOT EXISTS idx_eam_agent_user ON eam_field_agent (user_id);
CREATE INDEX IF NOT EXISTS idx_eam_agent_region ON eam_field_agent (region_id);
DROP TRIGGER IF EXISTS trg_eam_agent_updated_at ON eam_field_agent;
CREATE TRIGGER trg_eam_agent_updated_at BEFORE UPDATE ON eam_field_agent FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- agent ↔ group (many-to-many)
CREATE TABLE IF NOT EXISTS eam_field_agent_group_rel (
    agent_id UUID NOT NULL REFERENCES eam_field_agent(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES eam_field_agent_group(id) ON DELETE CASCADE,
    PRIMARY KEY (agent_id, group_id)
);
-- agent ↔ kawasan coverage (many-to-many)
CREATE TABLE IF NOT EXISTS eam_field_agent_kawasan_rel (
    agent_id   UUID NOT NULL REFERENCES eam_field_agent(id) ON DELETE CASCADE,
    kawasan_id UUID NOT NULL REFERENCES eam_kawasan(id) ON DELETE CASCADE,
    PRIMARY KEY (agent_id, kawasan_id)
);
-- group ↔ kawasan coverage (many-to-many)
CREATE TABLE IF NOT EXISTS eam_field_agent_group_kawasan_rel (
    group_id   UUID NOT NULL REFERENCES eam_field_agent_group(id) ON DELETE CASCADE,
    kawasan_id UUID NOT NULL REFERENCES eam_kawasan(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, kawasan_id)
);

CREATE TABLE IF NOT EXISTS eam_field_agent_leave (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                VARCHAR(64),
    agent_id            UUID         NOT NULL REFERENCES eam_field_agent(id) ON DELETE CASCADE,
    user_id             UUID         REFERENCES users(id),
    leave_type          VARCHAR(12)  NOT NULL DEFAULT 'annual',
    date_from           DATE         NOT NULL,
    date_to             DATE         NOT NULL,
    reason              TEXT,
    state               VARCHAR(12)  NOT NULL DEFAULT 'draft',
    approved_by         UUID         REFERENCES users(id),
    approval_date       TIMESTAMPTZ,
    rejection_reason    TEXT,
    active              BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id          UUID         REFERENCES companies(id),
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_leave_type CHECK (leave_type IN ('annual','medical','emergency','training','unpaid','other')),
    CONSTRAINT chk_eam_leave_state CHECK (state IN ('draft','submitted','approved','rejected','cancelled')),
    CONSTRAINT chk_eam_leave_dates CHECK (date_to >= date_from)
);
CREATE INDEX IF NOT EXISTS idx_eam_leave_agent ON eam_field_agent_leave (agent_id, date_from DESC);
DROP TRIGGER IF EXISTS trg_eam_leave_updated_at ON eam_field_agent_leave;
CREATE TRIGGER trg_eam_leave_updated_at BEFORE UPDATE ON eam_field_agent_leave FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ============================================================================
-- Approval framework (§3.10) — generic, resource-agnostic so it does not
-- depend on the (not-yet-built) generic asset register (§3.9). The resource
-- is referenced by (resource_model, resource_id).
-- ============================================================================
CREATE TABLE IF NOT EXISTS eam_approval_matrix (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                VARCHAR(160) NOT NULL,
    company_id          UUID         REFERENCES companies(id),
    transaction_type    VARCHAR(16)  NOT NULL,
    min_value           NUMERIC(18,2),
    max_value           NUMERIC(18,2),
    level_1_role_id     UUID         REFERENCES roles(id),
    level_2_role_id     UUID         REFERENCES roles(id),
    level_3_role_id     UUID         REFERENCES roles(id),
    active              BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_apmx_txn CHECK (transaction_type IN ('activation','disposal','transfer','revaluation'))
);
DROP TRIGGER IF EXISTS trg_eam_apmx_updated_at ON eam_approval_matrix;
CREATE TRIGGER trg_eam_apmx_updated_at BEFORE UPDATE ON eam_approval_matrix FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TABLE IF NOT EXISTS eam_approval_request (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                VARCHAR(64),
    resource_model      VARCHAR(60)  NOT NULL,
    resource_id         UUID         NOT NULL,
    resource_name       VARCHAR(200),
    company_id          UUID         REFERENCES companies(id),
    transaction_type    VARCHAR(16)  NOT NULL,
    matrix_id           UUID         REFERENCES eam_approval_matrix(id) ON DELETE SET NULL,
    requested_by        UUID         NOT NULL REFERENCES users(id),
    request_date        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    state               VARCHAR(12)  NOT NULL DEFAULT 'pending',
    notes               TEXT,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_eam_apreq_txn CHECK (transaction_type IN ('activation','disposal','transfer','revaluation')),
    CONSTRAINT chk_eam_apreq_state CHECK (state IN ('pending','approved','rejected','cancelled'))
);
CREATE INDEX IF NOT EXISTS idx_eam_apreq_resource ON eam_approval_request (resource_model, resource_id);
CREATE INDEX IF NOT EXISTS idx_eam_apreq_state ON eam_approval_request (state);
DROP TRIGGER IF EXISTS trg_eam_apreq_updated_at ON eam_approval_request;
CREATE TRIGGER trg_eam_apreq_updated_at BEFORE UPDATE ON eam_approval_request FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TABLE IF NOT EXISTS eam_approval_line (
    id                  UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    request_id          UUID         NOT NULL REFERENCES eam_approval_request(id) ON DELETE CASCADE,
    sequence            INTEGER      NOT NULL DEFAULT 0,
    approval_role_id    UUID         REFERENCES roles(id),
    approver_id         UUID         REFERENCES users(id),
    approval_date       TIMESTAMPTZ,
    state               VARCHAR(12)  NOT NULL DEFAULT 'pending',
    notes               TEXT,
    CONSTRAINT chk_eam_apln_state CHECK (state IN ('pending','approved','rejected'))
);
CREATE INDEX IF NOT EXISTS idx_eam_apln_request ON eam_approval_line (request_id, sequence);

-- ============================================================================
-- Wire deferred FKs from Phase 4 (eam_maintenance.plan_id / field_agent_group_id)
-- ============================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_eam_mnt_plan') THEN
        ALTER TABLE eam_maintenance ADD CONSTRAINT fk_eam_mnt_plan FOREIGN KEY (plan_id) REFERENCES eam_maintenance_plan(id) ON DELETE SET NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_eam_mnt_agent_group') THEN
        ALTER TABLE eam_maintenance ADD CONSTRAINT fk_eam_mnt_agent_group FOREIGN KEY (field_agent_group_id) REFERENCES eam_field_agent_group(id) ON DELETE SET NULL;
    END IF;
END$$;

-- ============================================================================
-- Security roles (§6) — two ladders. Inheritance is enforced in the handlers;
-- here we register the six groups as system roles with permission patterns.
-- ============================================================================
INSERT INTO roles (id, company_id, name, description, permissions, is_system) VALUES
    ('5e5b0000-0000-0000-0000-0000000000a1', NULL, 'EAM User',
     'Read assets; create/edit maintenance, inspections, defects, patrols',
     '["sesb_eam.read.*","sesb_eam.operational.write"]', true),
    ('5e5b0000-0000-0000-0000-0000000000a2', NULL, 'EAM Officer',
     'Manage equipment/plans; verify maintenance/inspection; run annual plan generator',
     '["sesb_eam.read.*","sesb_eam.operational.write","sesb_eam.hierarchy.write","sesb_eam.plan.write","sesb_eam.maintenance.verify"]', true),
    ('5e5b0000-0000-0000-0000-0000000000a3', NULL, 'EAM Manager',
     'Full CRUD on operational data; approve assets; cancel/reset',
     '["sesb_eam.*","sesb_eam.asset.approve","sesb_eam.delete"]', true),
    ('5e5b0000-0000-0000-0000-0000000000a4', NULL, 'EAM Admin',
     'Config (manufacturers, voltage levels, asset types); unlock plan frequency',
     '["sesb_eam.*","sesb_eam.config.*","sesb_eam.plan.unlock_frequency"]', true),
    ('5e5b0000-0000-0000-0000-0000000000a5', NULL, 'EAM Asset Creator',
     'Create/submit the asset hierarchy for verification; no work-order access',
     '["sesb_eam.read.config","sesb_eam.hierarchy.write","sesb_eam.asset.submit"]', true),
    ('5e5b0000-0000-0000-0000-0000000000a6', NULL, 'EAM Asset Verifier',
     'Verify/reject submitted assets; no work-order access',
     '["sesb_eam.read.config","sesb_eam.hierarchy.read","sesb_eam.asset.verify"]', true)
ON CONFLICT (company_id, name) DO NOTHING;

-- Runtime role grants
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON
            eam_maintenance_plan, eam_field_agent, eam_field_agent_group,
            eam_field_agent_group_rel, eam_field_agent_kawasan_rel,
            eam_field_agent_group_kawasan_rel, eam_field_agent_leave,
            eam_approval_matrix, eam_approval_request, eam_approval_line TO vortex_runtime';
    END IF;
END$$;
