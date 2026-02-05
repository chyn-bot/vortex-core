-- Database Manager: managed database registry and configuration
-- Applied only to the master database for multi-database management

CREATE TABLE IF NOT EXISTS managed_databases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(63) NOT NULL UNIQUE,
    display_name VARCHAR(255),
    state VARCHAR(20) NOT NULL DEFAULT 'active',
    demo_data BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_accessed_at TIMESTAMPTZ,
    size_bytes BIGINT,
    notes TEXT
);

CREATE INDEX idx_managed_databases_state ON managed_databases (state);
CREATE INDEX idx_managed_databases_name ON managed_databases (name);

CREATE TABLE IF NOT EXISTS db_manager_config (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL
);

-- Reverse migration
-- DROP TABLE IF EXISTS db_manager_config;
-- DROP TABLE IF EXISTS managed_databases;
