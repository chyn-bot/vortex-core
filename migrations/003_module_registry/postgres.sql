-- Module Registry Schema
-- Tracks installed modules per database (Odoo-style app installation)

-- ============================================================================
-- INSTALLED MODULES (similar to Odoo's ir.module.module)
-- ============================================================================
CREATE TABLE installed_modules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,                    -- Human-readable name
    technical_name VARCHAR(255) NOT NULL UNIQUE,   -- Module identifier (e.g., 'contacts', 'inventory')
    version VARCHAR(50) NOT NULL,                  -- Semantic version
    state VARCHAR(50) NOT NULL DEFAULT 'uninstalled',  -- uninstalled, to_install, installed, to_upgrade, to_remove
    category VARCHAR(100),                         -- Module category
    summary VARCHAR(500),                          -- Short description
    description TEXT,                              -- Full description
    author VARCHAR(255),
    website VARCHAR(255),
    license VARCHAR(50),

    -- Module flags
    is_core BOOLEAN NOT NULL DEFAULT false,        -- Core module (cannot be uninstalled)
    auto_install BOOLEAN NOT NULL DEFAULT false,   -- Auto-install when dependencies are met
    application BOOLEAN NOT NULL DEFAULT false,    -- Is this a main application vs utility

    -- Installation tracking
    installed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ,
    installed_by UUID REFERENCES users(id),

    -- Sequence for display order
    sequence INTEGER DEFAULT 100,

    -- Icon/image for UI
    icon VARCHAR(255),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_module_state CHECK (state IN ('uninstalled', 'to_install', 'installed', 'to_upgrade', 'to_remove'))
);

CREATE INDEX idx_installed_modules_state ON installed_modules(state);
CREATE INDEX idx_installed_modules_category ON installed_modules(category);
CREATE INDEX idx_installed_modules_technical_name ON installed_modules(technical_name);

-- ============================================================================
-- MODULE DEPENDENCIES (similar to Odoo's ir.module.module.dependency)
-- ============================================================================
CREATE TABLE module_dependencies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    module_id UUID NOT NULL REFERENCES installed_modules(id) ON DELETE CASCADE,
    depends_on VARCHAR(255) NOT NULL,              -- Technical name of dependency
    version_constraint VARCHAR(100),               -- e.g., ">=1.0.0", "^2.0"
    optional BOOLEAN NOT NULL DEFAULT false,       -- Optional dependency (nice-to-have)
    auto_install_trigger BOOLEAN NOT NULL DEFAULT false,  -- When this is installed, auto-install parent

    UNIQUE(module_id, depends_on)
);

CREATE INDEX idx_module_dependencies_module ON module_dependencies(module_id);
CREATE INDEX idx_module_dependencies_depends ON module_dependencies(depends_on);

-- ============================================================================
-- MODULE DATA (tracks records created by module for clean uninstall)
-- ============================================================================
CREATE TABLE module_data (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    module_id UUID NOT NULL REFERENCES installed_modules(id) ON DELETE CASCADE,
    model_name VARCHAR(255) NOT NULL,              -- Table/model name
    record_id UUID NOT NULL,                       -- ID of the record
    xml_id VARCHAR(255),                           -- External identifier (like Odoo's xml_id)
    noupdate BOOLEAN NOT NULL DEFAULT false,       -- Don't update on module upgrade

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(model_name, record_id)
);

CREATE INDEX idx_module_data_module ON module_data(module_id);
CREATE INDEX idx_module_data_xml_id ON module_data(xml_id) WHERE xml_id IS NOT NULL;
CREATE INDEX idx_module_data_model ON module_data(model_name, record_id);

-- ============================================================================
-- MODULE MIGRATIONS (tracks which migrations have been applied per module)
-- ============================================================================
CREATE TABLE module_migrations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    module_id UUID NOT NULL REFERENCES installed_modules(id) ON DELETE CASCADE,
    migration_name VARCHAR(255) NOT NULL,          -- Migration folder name
    version VARCHAR(50),                           -- Version this migration applies to
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    checksum VARCHAR(64),                          -- SHA256 of migration SQL
    execution_time_ms INTEGER,

    UNIQUE(module_id, migration_name)
);

CREATE INDEX idx_module_migrations_module ON module_migrations(module_id);

-- ============================================================================
-- CORE MODULES (pre-register essential modules)
-- ============================================================================
INSERT INTO installed_modules (
    technical_name, name, version, state, category,
    summary, is_core, application, sequence
) VALUES
    ('base', 'Base', '1.0.0', 'installed', 'Core',
     'Core framework - users, companies, roles, security', true, false, 1),
    ('access_control', 'Access Control', '1.0.0', 'installed', 'Core',
     'Role-based access control and record rules', true, false, 2);

-- Register core module dependencies
INSERT INTO module_dependencies (module_id, depends_on)
SELECT id, 'base' FROM installed_modules WHERE technical_name = 'access_control';

-- ============================================================================
-- AVAILABLE MODULES (modules that can be installed)
-- These are registered but not installed by default
-- ============================================================================
INSERT INTO installed_modules (
    technical_name, name, version, state, category,
    summary, is_core, application, sequence
) VALUES
    ('contacts', 'Contacts', '1.0.0', 'uninstalled', 'Sales',
     'Manage customers, suppliers, and contacts', false, true, 10);

-- Contacts depends on base
INSERT INTO module_dependencies (module_id, depends_on)
SELECT id, 'base' FROM installed_modules WHERE technical_name = 'contacts';

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Function to check if a module is installed
CREATE OR REPLACE FUNCTION is_module_installed(p_technical_name VARCHAR)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM installed_modules
        WHERE technical_name = p_technical_name
        AND state = 'installed'
    );
END;
$$ LANGUAGE plpgsql;

-- Function to get all installed module names
CREATE OR REPLACE FUNCTION get_installed_modules()
RETURNS TABLE(technical_name VARCHAR, version VARCHAR) AS $$
BEGIN
    RETURN QUERY
    SELECT im.technical_name::VARCHAR, im.version::VARCHAR
    FROM installed_modules im
    WHERE im.state = 'installed'
    ORDER BY im.sequence, im.name;
END;
$$ LANGUAGE plpgsql;

-- Function to check if all dependencies are satisfied
CREATE OR REPLACE FUNCTION check_module_dependencies(p_technical_name VARCHAR)
RETURNS TABLE(
    dependency VARCHAR,
    is_satisfied BOOLEAN,
    required_version VARCHAR
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        md.depends_on::VARCHAR,
        EXISTS (
            SELECT 1 FROM installed_modules im2
            WHERE im2.technical_name = md.depends_on
            AND im2.state = 'installed'
        ),
        md.version_constraint::VARCHAR
    FROM installed_modules im
    JOIN module_dependencies md ON md.module_id = im.id
    WHERE im.technical_name = p_technical_name;
END;
$$ LANGUAGE plpgsql;
