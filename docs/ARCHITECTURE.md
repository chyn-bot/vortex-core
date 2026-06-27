# Vortex Architecture

**Status**: working document. Last updated 2026-04-11.
**Audience**: Vortex core developers, plugin authors, integrators.

---

## 1. What Vortex is

Vortex is a **horizontal ERP platform** written in Rust. It is intentionally not bound to any industry — the core provides a zero-trust kernel (identity, persistence, audit, policy, workflow, multi-tenancy, plugin loading) and every domain-specific capability ships as a **plugin crate**.

Verticals ship as plugin crates. The in-tree examples are Change Request (`vortex-change`), a cross-cutting plugin, and Contacts (`vortex-contacts`), a CRM-style reference plugin. More verticals will follow — manufacturing, retail, services, finance, public sector — each as its own crate, including third-party ones built against the plugin SDK.

Vortex is closer in spirit to **Odoo** (horizontal ERP with vertical modules) than to NetSuite or SAP: open, modular, auditable, self-hostable, and designed so third parties can build verticals without touching core.

## 2. The platform/vertical split

The single most important architectural rule in this project:

> **Core is horizontal. Verticals are plugins. Nothing in core knows which plugins exist.**

### What belongs in core

Anything that two different verticals would both need:

| Concern | Where | Status |
|---|---|---|
| Users, roles, sessions, auth | `vortex-security`, `vortex-framework` | shipped |
| Companies / tenants / multi-DB | `vortex-framework`, `vortex-module` | shipped (Phase 0, migration 107) |
| Partners / contacts (res_partner equivalent) | core migration `010_contacts` | shipped, but light |
| ORM and `#[derive(Model)]` | `vortex-orm`, `vortex-macros` | shipped |
| WORM audit ledger with cryptographic chain | `vortex-security::audit` | shipped (Phase 0.1) |
| Cedar ABAC policy engine | `vortex-policy` | shipped (Phase 0.2) |
| Generic workflow state-machine engine | `vortex-workflow` | shipped (Phase 0.4) |
| Plugin registry / loader / install state | `vortex-framework`, `vortex-module` | shipped (Phase 0.3) |
| Mail / notification bus (chatter) | `vortex-chatter` | shipped (migration 020) |
| HTTP shell, middleware, sidebar, menu system | `vortex-server`, `vortex-framework` | shipped |
| CLI host binary | `vortex-cli` | shipped |

### What belongs in a plugin

Anything industry-, regulator-, or geography-specific:

- Industry domain models (leads, invoices, patient records, production orders)
- Industry-specific workflows
- Vertical compliance profiles (SOX, HIPAA, PCI-DSS, GDPR shapes) — configured on top of core primitives
- Industry vocabulary, UI, reports
- Regulator-specific audit formats (CEF/LEEF export presets)

### What's *almost* core but missing today

Things a horizontal ERP must have that are **not yet in core** and will gate a second vertical:

| Capability | Odoo analogue | Current state | Priority |
|---|---|---|---|
| Universal sequence service | `ir.sequence` | **Shipped** — promoted into core as the `vortex-orm` sequence service; any plugin can request sequence generation. | — |
| Currency / exchange rates | `res.currency` | **Shipped (Phase 0.7)** — `currencies` + `currency_rates` + `companies.currency_id` (migration 119). API: `vortex_orm::commerce::{Currency, CurrencyRate, get_rate, convert_amount, round_to_currency}`. | — |
| Taxes | `account.tax` | **Shipped (Phase 0.7)** — minimal model: percent/fixed, sale/purchase/none, inclusive/exclusive. Compound taxes and tax groups deferred. API: `vortex_orm::commerce::{Tax, TaxAmountType, TaxTypeUse, compute_tax_amount}`. | — |
| Unit of measure | `uom.uom` | **Shipped (Phase 0.7)** — category-scoped conversion graph, 6 seed categories, ~29 seed units. API: `vortex_orm::commerce::{UomCategory, Uom, convert_uom}`. | — |
| Chart of accounts / journals | `account.*` | Not present | P1 (foundation for any finance module) |
| Scheduled actions / cron | `ir.cron` | Not present | P0 |
| Report engine (HTML/CSV/JSON) | QWeb reports | **Shipped (Phase 0.7)** — `vortex_framework::reports` registry + `GET /reports/:code` endpoint + `ReportDef` plugin contribution. HTML/CSV/JSON only; PDF and XLSX deferred to extension plugins. | — |
| Per-tenant configuration UI | `res.config.settings` | Not present | P1 |
| i18n / translations | `ir.translation` | **Shipped (Phase 0.7)** — `translations` table + `TranslationService` + `Locale` type + format helpers + `Plugin::translations()`. Seeds EN + MS. Deferred: template filters, pluralization, RTL. | — |
| Settings-driven UI (studio-lite) | Odoo Studio | Not present | P2 |

> These should be filled in **before** starting a second vertical. Building, say, a CRM plugin without a scheduled-actions framework means the CRM will reinvent it, and then every plugin after that will too.

## 3. The Plugin contract

Every vertical implements `vortex_framework::Plugin` (see [`crates/vortex-framework/src/plugin.rs`](../crates/vortex-framework/src/plugin.rs)):

```rust
#[async_trait]
pub trait Plugin: Send + Sync {
    fn technical_name(&self) -> &'static str;
    fn display_name(&self) -> &'static str;
    fn version(&self) -> &'static str;

    fn routes(&self) -> Router<Arc<AppState>>            { Router::new() }
    fn nested_services(&self) -> Vec<(String, Router)>   { vec![] }
    fn menu_entries(&self) -> Vec<MenuEntry>             { vec![] }
    fn state_machines(&self) -> Vec<StateMachine>        { vec![] }
    fn migrations(&self) -> Vec<PluginMigration>         { vec![] }

    async fn on_startup(&self, _state: &AppState) -> VortexResult<()> { Ok(()) }
}
```

A plugin contributes:

1. **Identity** — stable `technical_name` (snake_case) used to key the `installed_modules` table and namespace its migration history.
2. **HTTP routes** — an `axum::Router` fragment `merge`d into the host router. Plugin owns its URL layout.
3. **Nested sub-services** — routers with their own state that get `nest_service`d at a chosen prefix (e.g. a CRM plugin mounting `/api/crm/*` with its own per-request `DatabaseContext`).
4. **Sidebar menu entries** — host aggregates, sorts by group+priority, role-filters, and renders.
5. **Workflow state machines** — registered into the shared `WorkflowEngine` during startup.
6. **Migrations** — embedded via `include_str!` so the plugin crate is self-contained; the migration runner records applied migrations under a composite key `<technical_name>:<migration_name>`, so plugins can have collisions in local names without conflict.
7. **Startup hook** — async, runs after registration but before routes mount. Used to load Cedar policies, prime caches, seed optional defaults.

### Plugin migration contract

Plugins ship SQL with `include_str!` — no copying files into the host's `migrations/` directory. Each `PluginMigration` declares:
- `name` — plugin-local, zero-padded (`001_foo`).
- `up_sql` / `down_sql` — embedded SQL strings.
- `requires_core_migration` — the last core migration the plugin depends on. The runner fails fast with a clear error if core is older, instead of producing a confusing `relation "foo" does not exist`.

This contract was established in Phase 0.6 ("The Great Extraction"). As of Phase 0.7 every in-tree plugin (`vortex-change`, `vortex-contacts`) ships its migrations through it; no plugin-specific SQL lives in `vortex-core/migrations/` anymore.

## 4. The platform ABI: `AppState`

`vortex_framework::AppState` is the single type that crosses the boundary between the host binary and every plugin. It is the **platform ABI** and must be treated with corresponding care — adding a field recompiles the workspace, removing one breaks every plugin.

Current fields (see [`crates/vortex-framework/src/state.rs`](../crates/vortex-framework/src/state.rs)):

| Field | Purpose |
|---|---|
| `db: PgPool` | Primary Postgres pool |
| `pool: Arc<ConnectionPool>` | `vortex-orm` wrapper over the pool |
| `pool_manager: Arc<DatabasePoolManager>` | Per-tenant pool registry for multi-DB mode |
| `master_db: Option<PgPool>` | Master DB for the multi-tenant registry |
| `master_password_hash: Option<String>` | Master-mode admin password (Argon2) |
| `db_filter: Option<String>` | Regex filter for which managed DBs the login page lists |
| `multi_db: bool` | Multi-database mode flag |
| `default_db: String` | Single-tenant fallback DB name |
| `installed_modules: Arc<RwLock<HashSet<String>>>` | Live cache of installed module technical names |
| `audit: Arc<AuditLog>` | WORM audit ledger (Phase 0.1) |
| `policy: Arc<PolicyService>` | Cedar ABAC engine (Phase 0.2) |
| `workflow: Arc<WorkflowEngine>` | Generic state-machine engine (Phase 0.4) |
| `plugin_registry: Arc<PluginRegistry>` | Registry of all loaded plugins (Phase 0.3) |

Rules for evolving `AppState`:

1. **Add fields only for things that are genuinely cross-cutting.** If one plugin needs it, it goes on that plugin's own struct.
2. **Never remove a field once stable.** Deprecate, leave in place, eventually roll into a major version bump with a migration note.
3. **Per-request state** (like the current tenant DB pool) goes in `DatabaseContext` in request extensions, not in `AppState`.

## 5. Deployment shapes

Vortex is designed for three distinct deploy shapes. Any future packaging work must serve all three.

### Shape 1 — SaaS operator

**You run the software, customers get tenants.**

- One `vortex` binary, one Postgres cluster.
- `database_manager` provisions per-tenant databases (`vortex_acme`, `vortex_globex`, …) from the master DB.
- Tenants pick verticals per-database: `vortex module install crm -d vortex_acme`.
- Auth middleware routes each request to the tenant's pool via `DatabaseContext`.
- Reverse proxy (nginx/Caddy) terminates TLS, maps subdomain → tenant.

**Packaging**: container image **or** a fat binary + systemd unit. External Postgres (not bundled).

### Shape 2 — On-prem, single customer

**Customer runs the software on their own infrastructure.**

- Same binary, single database, single tenant.
- Customer's IT team installs via `.deb` / `.rpm` / MSI.
- Post-install runs `vortex db init && vortex db migrate`.
- Customer (or their SI) runs `vortex module install <vertical>` to enable the modules they bought.
- Optionally air-gapped — the binary must not require internet to start, register, or validate licenses.

**Packaging**: native OS packages (`.deb`, `.rpm`, Windows MSI) with systemd unit / Windows service wrapper. Postgres as a declared dependency, not bundled.

This is the shape regulated enterprise customers will want — factories, hospitals, financial institutions, public-sector customers — anyone who won't let software run in someone else's cloud.

### Shape 3 — Developer / plugin author

**A person building a new vertical.**

- `git clone`, `cargo run -p vortex-cli -- server`, local Postgres.
- `docker-compose up` provides the Postgres dependency only.
- Seed data and sample tenant.
- This is where Docker Compose legitimately earns its place — for dev, not production.

**Packaging**: checked-in `docker-compose.yml` targeting Postgres only, plus scripted seed data. A plugin template repo (`cargo generate vortex-plugin`) lives in its own repo, not this one.

### Things every shape needs

- Static binary or minimal-dependency binary — `sqlx` pure-Rust Postgres, no libpq linkage (`x86_64-unknown-linux-musl` target works today).
- Config via `vortex.toml` + environment variables. Secrets (JWT, audit signing key, master password) via env only, never checked into the config file.
- Migration runner bundled in the binary, not as a separate artifact.
- `vortex info` / `vortex db status` commands for post-install diagnostics.
- Log format configurable (human-readable vs JSON) and routable to file or stdout.

## 6. Install story (today)

This is the actual path on a fresh Linux server with the current codebase:

```bash
# Prereqs
apt-get install -y build-essential pkg-config libssl-dev postgresql-16
curl https://sh.rustup.rs -sSf | sh

# Source + build
git clone <vortex-core-remote>.git
cd vortex-core
cargo build --release -p vortex-cli
install -m 0755 target/release/vortex /usr/local/bin/vortex

# DB
sudo -u postgres createuser vortex -P
sudo -u postgres createdb -O vortex vortex

# Config
install -d /etc/vortex /var/lib/vortex
cp vortex.toml /etc/vortex/
# edit: database.url, jwt_secret, master_password, db_filter

# Secrets (env-only)
export VORTEX_AUDIT_SIGNING_KEY=$(openssl genpkey -algorithm Ed25519 \
  | openssl pkcs8 -topk8 -nocrypt -outform DER | base64 -w0)

# Apply schema
vortex db init
vortex db migrate

# Bootstrap admin
vortex user create admin admin@example.com --admin

# Run
vortex server -H 0.0.0.0 -p 3000
```

This works. What's missing before it's truly "installable elsewhere":

- **No systemd unit** checked in.
- **No `.deb` / `.rpm`** packaging.
- **No installer script** — the commands above are manual.
- **Audit signing key** is still env-var-sourced; production needs KMS/HSM integration.
- **No license/entitlement gating** — `vortex module install <vertical>` is unrestricted; commercial verticals will need an entitlement check.

## 7. Known gaps (as of 2026-04-11)

These are architectural debt items to close before scaling to multiple verticals:

1. ~~**Plugin-specific migrations in core.**~~ **Done (Phase 0.7).** No vertical migrations live in `vortex-core/migrations/` anymore. Every plugin contributes its schema entirely from within its own crate via `Plugin::migrations()` and the `PluginMigration` contract, tracked under a composite key `<technical_name>:<migration_name>`. Core can be installed standalone with zero vertical tables.
2. ~~**Sequence service should be promoted to core.**~~ **Done.** Sequence generation now lives in `vortex-orm` as a core service, available to every plugin; no vertical owns its own copy.
3. **No scheduled-actions / cron framework.** Every vertical will need this. *(Impact: blocks more verticals.)*
4. ~~**No currency / UoM / tax primitives.**~~ **Done (Phase 0.7).** Migration `119_commerce_primitives` ships `currencies` (+ ISO 4217 seeds), `currency_rates` (time-series with `rate=1` baseline for every currency), `uom_categories` + `uoms` (6 categories, ~29 units), `taxes` (minimal percent/fixed model), and adds `companies.currency_id`. Rust API lives at `vortex_orm::commerce`: pure-function conversion/rounding (`convert_uom`, `compute_tax_amount`, `round_to_currency`) plus DB-backed rate lookup (`get_rate`, `convert_amount`). 19 unit tests cover the pure logic paths. **Deferred**: compound taxes, tax groups, rate-provider integration (natural fit for a scheduled action), chart of accounts, journal entries.
5. ~~**No report engine.**~~ **Partially done (Phase 0.7).** `vortex_framework::reports` ships a registry + `GET /reports/:code` endpoint + `ReportDef` plugin contribution with HTML, CSV, and JSON formats. Every render is audited via `AuditAction::BulkExport`. Plugins declare reports in one block via `Plugin::reports()` and get HTTP delivery for free; direct consumers (scheduled email, export scripts) call `render_report(state, code, params)` to get the same bytes without HTTP. **Still deferred**: PDF and XLSX. These belong in extension plugins (`vortex-report-pdf`, `vortex-report-xlsx`) that wrap specific backends without forcing every Vortex deployment to carry a heavyweight dependency. For internal reports today, handlers generate HTML with `@media print` stylesheets and users Ctrl+P → Save as PDF from the browser. Regulated customer-facing artifacts (legal invoices, tax returns) requiring guaranteed PDF output wait for the extension plugin.
6. ~~**Audit signing key is env-sourced.**~~ **Done (Phase 0.7).** `vortex-security::signing` restructured from a single `signing.rs` into a `signing/` module with pluggable backends: `Ed25519Key` (env-var, dev-only) and `Pkcs11SigningKey` (PKCS#11 v3.0, works with SoftHSM2 for dev/CI, Thales Luna / Entrust nShield / YubiHSM 2 / Utimaco for production). Backend selection via `[audit.signing]` in `vortex.toml`. Private key material NEVER enters the Vortex process with the PKCS#11 backend. Extension contract documented in `signing/mod.rs` header — adding Vault / AWS KMS / Azure Key Vault is four additive steps, no existing backend code is touched. **Still deferred**: ECDSA-P256 algorithm support (for HSMs with pre-FIPS-186-5 firmware), automated key rotation ceremony, KMS-backed unseal for multi-DB deployments.
7. ~~**No i18n framework.**~~ **Done (Phase 0.7).** `vortex_framework::i18n` ships `Locale` (BCP 47 parsing, fallback chain), `TranslationService` (in-memory cache from `translations` DB table, `t(key, locale)` with fallback), locale-aware `format_date` and `format_number` helpers, `Plugin::translations()` hook, and `users.locale` / `companies.locale` columns (migration 120). Seeds 28 core keys in English + Malay. **Deferred**: Askama template `{{ t("key") }}` filter, pluralization rules, RTL layout, full CLDR via ICU4X, translation admin UI.
8. ~~**Plugin SDK not extracted.**~~ **Done (Phase 0.7).** `crates/vortex-plugin-sdk/` is a thin re-export facade over the six core crates (common, framework, orm, security, workflow, policy) plus pinned versions of axum/sqlx/serde/chrono/uuid/tokio/tracing/rust_decimal. Third-party plugins depend on `vortex-plugin-sdk` alone and get the full `Plugin` contract (routes, menus, migrations, translations, scheduled actions, reports) through `use vortex_plugin_sdk::prelude::*`. A compile test (`tests/minimal_plugin.rs`) proves the prelude covers every `Plugin` trait method. In-tree plugins may continue to depend on individual crates directly.
9. ~~**Multi-DB audit writes to primary pool only.**~~ **Done (Phase 0.7).** `PgAuditStorage` now accepts an optional `DatabasePoolManager`. When an `AuditEntry` carries a `db_name` (set via `.with_database(name)`), the write resolves the tenant's pool from the manager and writes to that database's `audit_log`. System events (no `db_name`) continue to write to the primary. Server startup passes the pool manager to audit storage when multi-DB is enabled. The login handler demonstrates the pattern with `.with_database(&db_name)` on the `LoginSuccess` entry. Other handlers should adopt the same pattern as they are updated for multi-tenant correctness.
10. **No verification cron.** WORM chain verification is CLI-only today; should run on a schedule and page an operator on divergence.

## 8. Non-goals

- **We are not rebuilding Odoo's code.** We are matching the *model* (horizontal core, vertical modules, multi-tenant, auditable) but with a Rust-first, zero-trust, regulated-industry-ready posture. Python dynamism and Odoo's ORM tricks are not goals.
- **We are not building a visual IDE.** Maybe eventually, not now.
- **We are not targeting consumers.** Target users are regulated enterprises and the integrators who serve them.
- **We are not cloud-only.** On-prem must always be a first-class deployment shape, including air-gapped.

## 9. Glossary

| Term | Meaning |
|---|---|
| **Core** | The horizontal ERP kernel — every `vortex-*` crate other than a plugin. |
| **Vertical** | An industry-specific plugin crate (`vortex-change`, `vortex-contacts`, future: `vortex-crm`, `vortex-finance`, …). |
| **Plugin** | Any crate implementing `vortex_framework::Plugin`. All verticals are plugins; some cross-cutting capabilities may also be plugins. |
| **Tenant** | A customer database in multi-DB mode. In single-tenant mode there's exactly one, named `default_db`. |
| **Module** | Synonym for plugin in user-facing contexts — `vortex module install foo` installs the plugin with technical_name `foo` for a given tenant. |
| **WORM** | Write-Once, Read-Many — applied to the audit ledger. DB-level triggers forbid UPDATE/DELETE on `audit_log`. |
| **Vertical compliance profile** | A configuration of core compliance primitives (audit, eSig, policy) to match a specific regulator (SOX, HIPAA, PCI-DSS, GDPR, …). |
