# Vortex Blueprints — Phase 0–1 Implementation Plan

**Scope:** foundations (Phase 0) + governed model/field CRUD with a minimal builder UI (Phase 1). At the end of Phase 1 an admin can create a Blueprint in the browser and immediately get an audited, policy-gated, fully-featured CRUD app through the *existing* generic views.

**Decisions locked:** name **Blueprints**; storage = **generated physical tables** (`x_<name>`, one real column per field).

**Grounding facts (verified in tree):**
- Next core migration number is **145** (last is `144_portal_invites`).
- Standard model system columns: `id UUID PK DEFAULT uuid_generate_v4()`, `company_id UUID REFERENCES companies(id)`, `active BOOLEAN NOT NULL DEFAULT TRUE`, `created_at/updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()`, optional `created_by/updated_by UUID REFERENCES users(id)`.
- `ir_model_field.field_type` CHECK vocabulary: `string,char,text,boolean,integer,float,decimal,monetary,number,date,datetime,selection,many2one,one2many,many2many,uuid,json,binary`.
- **No runtime physical-DDL exists yet** — custom fields store values in JSONB, not columns. Blueprints are the first `CREATE TABLE`/`ALTER TABLE`-at-runtime path, so the DDL service is net-new and security-critical.
- `validate_identifier` currently lives **only** in `vortex-cli/src/commands/server.rs:4210` (private). Needs a shared home.
- Governance call shapes: `AuditEntry::new(action, severity).…; state.audit.log(entry).await` and `state.policy.check(&principal, action_name, &resource).await -> Decision`.

**Crate layering rule for this feature:**
- `vortex-orm::blueprint` = **pure schema mechanics** (identifier validation, DDL composition/execution, `blueprint_ddl_log`, registry upsert). *No* dependency on audit/policy.
- `vortex-framework::blueprint` + CLI handlers = **governance wrapper** (policy.check → orm mechanics → audit.log → bookkeeping). This is where `AppState` (audit, policy) is available.

---

## Phase 0 — Foundations (no UI)

### 0.1 Migration `145_blueprints`

`migrations/145_blueprints/postgres.sql` (+ `postgres_down.sql`):

```sql
-- Registry: distinguish the three kinds of field/model provenance.
ALTER TABLE ir_model
    ADD COLUMN IF NOT EXISTS source     VARCHAR(16) NOT NULL DEFAULT 'derived',
    ADD COLUMN IF NOT EXISTS is_virtual BOOLEAN     NOT NULL DEFAULT false;
ALTER TABLE ir_model_field
    ADD COLUMN IF NOT EXISTS source     VARCHAR(16) NOT NULL DEFAULT 'derived';

-- Backfill: existing custom fields become source='custom' so the registry
-- prune (which now owns only 'derived') stops depending on is_custom.
UPDATE ir_model_field SET source = 'custom' WHERE is_custom = true;

ALTER TABLE ir_model       ADD CONSTRAINT chk_ir_model_source
    CHECK (source IN ('derived','blueprint'));
ALTER TABLE ir_model_field ADD CONSTRAINT chk_ir_model_field_source
    CHECK (source IN ('derived','custom','blueprint'));

-- Blueprint definition metadata (beyond the ir_model row).
CREATE TABLE blueprint (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_id    UUID NOT NULL REFERENCES ir_model(id) ON DELETE CASCADE,
    company_id  UUID REFERENCES companies(id),
    status      VARCHAR(16) NOT NULL DEFAULT 'draft',   -- draft|active|archived
    icon        VARCHAR(64),
    description TEXT,
    created_by  UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_blueprint_model UNIQUE (model_id)
);

CREATE TABLE blueprint_version (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    blueprint_id UUID NOT NULL REFERENCES blueprint(id) ON DELETE CASCADE,
    version      INTEGER NOT NULL,
    definition   JSONB NOT NULL,
    applied_by   UUID REFERENCES users(id),
    applied_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_blueprint_version UNIQUE (blueprint_id, version)
);

-- Per-tenant DDL ledger: makes generated schema reproducible/verifiable,
-- mirrors vortex_migrations so Blueprints don't reopen the drift surface.
CREATE TABLE blueprint_ddl_log (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    blueprint_id UUID NOT NULL REFERENCES blueprint(id) ON DELETE CASCADE,
    statement    TEXT NOT NULL,
    applied_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

`postgres_down.sql`: drop the three tables, the two CHECKs, and the four columns. (Generated `x_*` tables are intentionally *not* dropped by the down migration — they hold data; document that.)

> Note: `144` already exists, so this slots cleanly. It touches only registry columns + new tables — no data risk to compiled models.

### 0.2 `vortex-orm::blueprint` — schema mechanics (new module `crates/vortex-orm/src/blueprint.rs`)

Public API (all `pub`, no audit/policy deps):

```rust
/// Reserved column/table names and the type vocabulary.
pub const SYSTEM_COLUMNS: &[&str] = &["id","company_id","active","created_at","updated_at","created_by","updated_by"];

/// Strict identifier check for anything interpolated into DDL. Lowercase
/// ascii, starts with a letter, `[a-z0-9_]{1,48}`, not a reserved word.
/// (Canonical home; the CLI's private copy should later delegate here.)
pub fn validate_identifier(name: &str) -> Result<(), BlueprintError>;

/// Map an ir_model_field.field_type to a Postgres column type.
/// string/char->VARCHAR(255), text->TEXT, boolean->BOOLEAN, integer->INTEGER,
/// float/number->DOUBLE PRECISION, decimal/monetary->NUMERIC(16,2),
/// date->DATE, datetime->TIMESTAMPTZ, uuid/many2one->UUID, json->JSONB, selection->VARCHAR(64).
fn column_type(field_type: &str) -> Result<&'static str, BlueprintError>;

/// Compose (never execute user SQL) + run CREATE TABLE x_<name> with the
/// standard system columns, inside `tx`. Writes blueprint_ddl_log.
pub async fn create_model_table(tx: &mut Transaction<'_, Postgres>, table: &str, blueprint_id: Uuid) -> Result<(), BlueprintError>;

/// ALTER TABLE x_<name> ADD COLUMN <col> <type> [NULL]. Rejects system/reserved names.
pub async fn add_column(tx, table, column, field_type, related_model: Option<&str>) -> Result<(), BlueprintError>;

/// ALTER TABLE … DROP COLUMN (guards system columns), RENAME COLUMN, etc.
pub async fn drop_column(tx, table, column) -> Result<(), BlueprintError>;
pub async fn rename_column(tx, table, from, to) -> Result<(), BlueprintError>;

/// DROP TABLE x_<name> (used by blueprint delete).
pub async fn drop_model_table(tx, table) -> Result<(), BlueprintError>;
```

Internals / rules:
- **Every** identifier (table, column, `related_model` FK target) passes `validate_identifier` *before* string composition; a `#[deny]`-style discipline — no `format!` of an unvalidated identifier. Add a `debug_assert` + a test that every public fn rejects `"x; drop table"`, `"1abc"`, `"Company"`, `"select"`, etc.
- Generated tables/columns are always **`x_` prefixed** at the service layer (the caller passes `x_<name>`); `validate_identifier` still runs on the full name.
- `many2one` columns are `UUID` + (Phase 3) a real FK; Phase 0/1 store the UUID without the FK constraint to keep the first cut simple (documented; FK added in Phase 3).
- Each executed statement is appended to `blueprint_ddl_log` **in the same tx**.
- `BlueprintError` (thiserror): `InvalidIdentifier`, `ReservedName`, `UnknownType`, `Db(sqlx::Error)`.

### 0.3 Registry prune change (`registry_sync.rs`)

Change the prune I shipped this session from `is_custom = false` to `source = 'derived'` so it owns only compiled-model fields and can never touch blueprint or custom rows:

```sql
DELETE FROM ir_model_field
WHERE model_id = $1 AND source = 'derived' AND name <> ALL($2)
```

Update the comment and the "legacy DB" fallback note (now keyed on the `source` column from migration 145). No behavior change for compiled models; makes Blueprints safe from the boot-time prune.

### 0.4 Phase 0 tests

- `blueprint.rs` unit tests (pure, no DB): `validate_identifier` accept/reject table; `column_type` mapping for the full vocabulary + unknown-type rejection.
- One DB-backed integration test (`#[ignore]` like the others, run against a scratch DB): `create_model_table` → `add_column` → row insert via a plain `INSERT` → `drop_column` → `drop_model_table`; assert `blueprint_ddl_log` captured each statement.
- `registry_sync` prune test updated to seed `source='blueprint'` + `source='custom'` rows and assert both survive while a stale `source='derived'` row is pruned (mirrors the manual acc_dev proof already done).

**Phase 0 exit:** migration applies; `cargo test -p vortex-orm` green; a REPL/CLI smoke can create a table via the service. No user-facing change yet.

---

## Phase 1 — Governed model/field CRUD + minimal builder UI

### 1.1 `vortex-framework::blueprint` — governed service (new module)

Wraps the orm mechanics with policy + audit + bookkeeping. One transaction per operation.

```rust
pub struct BlueprintService;   // stateless; takes &AppState-ish deps

/// Create a Blueprint: policy.check(Blueprint::Create) → begin tx →
/// insert ir_model (source='blueprint', is_virtual=true, table='x_<name>') →
/// orm::blueprint::create_model_table → insert blueprint + blueprint_version(v1)
/// → commit → audit.log(BlueprintCreated). Returns model name.
pub async fn create(state, user, name, label, company_id) -> Result<String, String>;

/// Add a field: policy.check(Blueprint::AlterField) → tx →
/// orm::add_column → insert ir_model_field(source='blueprint') → bump version
/// → commit → audit.log. Reuses registry_sync helpers for the ir_model_field row.
pub async fn add_field(state, user, model, field) -> Result<(), String>;

pub async fn rename_field(state, user, model, from, to) -> Result<(), String>;
pub async fn remove_field(state, user, model, name) -> Result<(), String>;
pub async fn delete(state, user, model) -> Result<(), String>;   // archive vs drop: default archive (is_active=false); hard-drop admin-only
```

- **Policy:** new Cedar action schema `Blueprint::{Create,AlterField,Delete}` registered in the system plugin's `on_startup` entity/action registration; `resource` = the model (or a `Blueprint` resource type). Deny → `403` before any DDL.
- **Audit:** `AuditEntry::new(AuditAction::…, AuditSeverity::Notice)` with `resource_type="blueprint"`, resource id = model name, and the field/DDL summary in metadata; `state.audit.log(entry).await` after commit. Schema changes are the marquee audit events.
- **Versioning:** every mutating op writes a `blueprint_version` snapshot (full field list JSON) for rollback/history.

### 1.2 Routes + handlers (`vortex-cli/src/commands/server.rs`)

```
GET  /blueprints                      -> list Blueprints (source='blueprint' models) + "New Blueprint"
GET  /blueprints/new                  -> create form (name, label, icon)
POST /blueprints                      -> BlueprintService::create → redirect /blueprints/{model}
GET  /blueprints/{model}              -> designer: field table + "Add field" + link "Open records" (/list/{model})
POST /blueprints/{model}/fields       -> add_field
POST /blueprints/{model}/fields/{name}/rename
POST /blueprints/{model}/fields/{name}/delete
POST /blueprints/{model}/delete       -> archive (or hard-drop for admin)
```

All handlers: admin/role-gated at the route (like other settings), then the service does the fine-grained Cedar check. Render with the **`render_app_shell`** primitive (from this session) + `build_sidebar`. Add a sidebar entry under Settings → "Blueprints".

### 1.3 The builder UI (minimal, vanilla JS + daisyUI, CSP-clean)

- **/blueprints** — table of Blueprints (label, technical name `x_…`, field count, status, created_by) + New button.
- **/blueprints/new** — name (→ slug → `x_<slug>`, live-validated against `validate_identifier`), label, icon.
- **/blueprints/{model}** — the designer:
  - field table (label, name, type, required) with Add / Rename / Delete;
  - "Add field" row: label + type dropdown (the fixed vocabulary) + required checkbox;
  - a prominent **"Open records →"** button to `/list/{model}` — the payoff: the generic list/form/kanban/pivot already work on the new model.
- No custom CSS framework; reuse `vortex.css`/`vortex.js`. Client-side identifier preview mirrors server `validate_identifier` (server is authoritative).

### 1.4 Phase 1 tests

- Service tests (DB-backed, `#[ignore]`): create Blueprint → assert `ir_model`(source=blueprint,is_virtual) + `x_<name>` table + `blueprint`+`blueprint_version` rows + audit entry; add_field → column exists + `ir_model_field`(source=blueprint) + version bumped; rename/remove; delete archives.
- Policy test: a principal without the Blueprint action is denied (no table created).
- **End-to-end on acc_dev** (manual, minted session like this session's verification): create a Blueprint `x_widget` with a couple of fields → `/list/x_widget` renders the generic list → create a record via `/form/x_widget/new` → row persists → pivot/kanban/calendar render → confirm a WORM audit entry for the schema change → delete/cleanup.

### 1.5 Verification & safety gates

- `cargo test -p vortex-orm -p vortex-framework -p vortex-cli` green; full workspace builds.
- Grep-audit: no `format!`/string-built identifier in the blueprint path that didn't pass `validate_identifier` (add a focused test).
- Confirm the boot-time registry sync does **not** prune blueprint fields (seed + restart, as in Phase 0.3).
- Confirm a Blueprint in tenant A is invisible in tenant B (per-tenant tables; run against two DBs).

---

## Sequencing / PR breakdown

1. **PR A (Phase 0):** migration 145 + `vortex-orm::blueprint` mechanics + prune `source` change + Phase 0 tests. Self-contained, no UI, low blast radius. Merge behind the existing green CI.
2. **PR B (Phase 1a):** `vortex-framework::blueprint` service + Cedar action schema + audit wiring + service tests. No routes yet.
3. **PR C (Phase 1b):** routes + builder UI + the end-to-end acc_dev verification. This is the demoable "create a model, get an app" milestone.

Each PR builds and tests independently; C is the one that ships user-visible capability.

## Implementation risks specific to Phase 0–1

- **DDL injection** is the whole ballgame — the single-service + `validate_identifier`-before-compose + fixed-vocabulary discipline must be airtight and tested adversarially. This is the code to review hardest.
- **Transaction boundaries:** ir_model/ir_model_field row and the physical DDL must commit together; a partial failure (table created, registry row not) leaves an orphan `x_` table. Do all-in-one-tx; on error, the tx rollback + a note that generated tables from a rolled-back tx don't persist (DDL is transactional in Postgres — good).
- **Prune interaction** (already handled by 0.3) — must land in the same release as the first blueprint, or a boot sync could prune blueprint fields. Ship Phase 0 first, always.
- **Rename/type-change semantics:** Phase 1 supports add/rename/drop only; a *type change* is deferred (needs a data migration path) — the UI should not offer it yet.
- **`validate_identifier` duplication:** Phase 0 adds the canonical one in `vortex-orm`; unifying the CLI's private copy is a follow-up cleanup, not a blocker.
