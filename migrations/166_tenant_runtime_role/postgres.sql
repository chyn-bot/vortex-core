-- Engage the least-privilege runtime role for the CURRENT tenant database.
--
-- Migration 114 created `vortex_runtime` and granted it least privilege over
-- the tables that existed then, revoking UPDATE/DELETE/TRUNCATE on the audit
-- tables so the WORM chain stays append-only. But (a) the application has
-- historically connected as the owner role, leaving that defence dormant, and
-- (b) dozens of tables have been added since 114 (accounting, inventory,
-- sales, blueprints, intake, rate_limit_bucket, …) that the role has no
-- explicit grants on.
--
-- This migration re-asserts the full least-privilege grant across ALL current
-- tables and sequences, re-applies the audit-table REVOKEs (the blanket GRANT
-- would otherwise re-grant mutation on audit_log), and grants the role CONNECT
-- so the server can `SET ROLE vortex_runtime` (VORTEX_DB_RUNTIME_ROLE) and run
-- with only these privileges. Idempotent, so `db migrate --all` back-fills
-- every existing tenant DB.
--
-- NOTE: this does not REVOKE CONNECT FROM PUBLIC — doing so safely requires
-- knowing every role that connects (owner + the app's login role), which is a
-- per-deployment fact. True per-tenant connect isolation (distinct login role
-- per tenant DB, wired through pool_manager credentials) is the follow-on.

DO $$
BEGIN
    -- Ensure the role exists (guarded: the migration role may lack CREATEROLE;
    -- an operator can pre-create `vortex_runtime` out-of-band instead).
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        BEGIN
            CREATE ROLE vortex_runtime LOGIN;
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE NOTICE 'vortex_runtime not created (migration role lacks CREATEROLE); pre-create it out-of-band to engage least-privilege.';
        END;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO vortex_runtime', current_database());

        -- Grant the CONNECTING role (the one running migrations / the app login,
        -- e.g. `vortex` or `remicle`) membership in vortex_runtime, so it is
        -- permitted to `SET ROLE vortex_runtime` at runtime. Without this,
        -- VORTEX_DB_RUNTIME_ROLE=vortex_runtime fails with "permission denied to
        -- set role" for any non-superuser connecting role. Guarded: skip if the
        -- migration role itself lacks the ADMIN OPTION / privilege to grant.
        BEGIN
            EXECUTE format('GRANT vortex_runtime TO %I', current_user);
        EXCEPTION WHEN insufficient_privilege OR OTHERS THEN
            RAISE NOTICE 'Could not GRANT vortex_runtime TO %; grant it out-of-band to enable SET ROLE isolation.', current_user;
        END;

        EXECUTE 'GRANT USAGE ON SCHEMA public TO vortex_runtime';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO vortex_runtime';
        EXECUTE 'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO vortex_runtime';
        -- Cover tables/sequences created by future migrations too.
        EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vortex_runtime';
        EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO vortex_runtime';

        -- Re-assert WORM append-only: the blanket GRANT above would otherwise
        -- hand back UPDATE/DELETE on the audit tables. INSERT stays (the ledger
        -- appends); mutation does not.
        EXECUTE 'REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM vortex_runtime';
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='audit_chain_head') THEN
            EXECUTE 'REVOKE DELETE, TRUNCATE ON audit_chain_head FROM vortex_runtime';
        END IF;
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name='audit_signing_keys') THEN
            EXECUTE 'REVOKE DELETE, TRUNCATE ON audit_signing_keys FROM vortex_runtime';
        END IF;
    END IF;
END$$;

-- Belt-and-suspenders regardless of the role: nobody may mutate the ledger.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM PUBLIC;
