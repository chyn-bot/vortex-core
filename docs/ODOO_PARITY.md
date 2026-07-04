# Core Readiness — Vortex vs the Odoo Framework Layer

Honest capability matrix against Odoo 19's framework (`odoo/` + the
framework addons: `base`, `mail`, `web`, `portal`, `base_import`),
compiled before starting module development. The question this
answers: **what does a module author get from Odoo's core that
Vortex's core doesn't give them yet?**

## Where Vortex is at parity — or ahead

| Capability | Odoo | Vortex | Notes |
|---|---|---|---|
| Sequences | `ir.sequence` | ✅ sequence service | per-tenant, padded codes |
| Cron | `ir.cron` | ✅ scheduler | plus a **durable job queue** (retry/backoff/dead-letter) Odoo core lacks |
| Attachments | `ir.attachment` | ✅ FileStore + attachments | S3-compatible out of the box; tenant-namespaced |
| Outbound mail | `ir.mail_server` | ✅ per-tenant SMTP | encrypted credentials |
| Chatter | `mail.thread` | ✅ chatter | messages, activities, attachments, secure view-only docs |
| Model registry | `ir.model` | ✅ `ir_model` | feeds list framework, report builder, REST API |
| Module lifecycle | `ir.module` | ✅ installed_modules | per-tenant install, plugin-owned migrations |
| Status bar | `statusbar` widget | ✅ `StatusBar` | stages DB-driven, admin-editable |
| Field tracking | `tracking=True` | ✅ `Tracker` | |
| List view | tree view | ✅ list framework | declarative: search/sort/filter/badges/group-by/paging |
| Reports | QWeb + report engine | ✅ | user-authored builder + sandboxed templates + PDF + **async pipeline with inbox** |
| Public pages | `portal`/`website` | ✅ `Plugin::public_routes()` | tenant-resolved, module-gated |
| Scaffolding | `odoo scaffold` | ✅ `vortex scaffold plugin` | generates a *working* module; CI-guarded |
| REST API | none native (RPC only) | ✅ `/api/v1` + scoped tokens | **ahead** |
| Webhooks | partial (17+) | ✅ signed, queue-delivered | |
| Audit | none tamper-evident | ✅ **WORM hash-chained ledger, HSM signing** | far ahead — this is the moat |
| Authorization engine | groups + `ir.rule` | ✅ Cedar ABAC | richer engine; see wiring gap below |
| Multi-tenancy | DB-per-tenant | ✅ DB-per-tenant | + connection budget, subdomain routing |
| Commerce types | currency/UoM/tax | ✅ `vortex_orm::commerce` | |
| i18n | deep | ⚠️ basic | sufficient for now |

## The real gaps, ranked

### 1. Declarative view layer — the blocker-grade gap
Odoo: define fields once → form/kanban/pivot/graph/calendar views
derive from them, with XML view inheritance. Vortex: list views are
declarative; **every form is hand-written HTML** and kanban/pivot
don't exist. This is the single largest difference in
module-developer cost — a vertical with 30 record types hand-writes
30 forms today.

Plan (already agreed): unify `#[derive(Model)]` with the `ir_model`
registry as the single source of truth, then `FormConfig` (widgets
inferred from field types, saves through the API's validated write
path, statusbar/chatter auto-mounted), then kanban, then pivot over
the existing aggregation engine. Odoo-style *view inheritance* is
phase two.

### 2. Generic data import — `base_import` equivalent
Every real deployment starts with "here's our Excel." Odoo ships
CSV/XLSX import with field mapping and dry-run validation on every
model. Vortex has nothing generic (export exists via reports/CSV).
Day-one need for any customer rollout; medium effort because the
model registry already knows the fields.

### 3. Real in-app notifications
`/api/notifications` currently returns **demo data** (TODO in code).
Chatter activities exist but nothing aggregates them into the bell.
Small, contained build: notifications table + count + mark-read,
fed by activities/approvals/report-ready events.

### 4. Model-level access wiring
The primitives exceed Odoo's (`Cedar`, plus `AccessChecker` /
`RecordRule` / `FieldAccess` in vortex-security) but they are not
*conventionally wired* — Odoo checks `ir.model.access` + record
rules on every ORM call automatically; Vortex handlers opt in via
`state.policy.check`. Fine for first-party discipline; must become
automatic (in the generic write path + view engine) before untrusted
third-party code.

### 5. Smaller, later
- **Email templates** (`mail.template`): per-model templated mail with
  placeholders — today mail is hand-formatted text.
- **Saved search filters** (`ir.filters`): list framework filters
  exist; user-saved favorites don't.
- **Per-tenant settings store** (`ir.config_parameter`): each feature
  builds its own settings table today; a generic KV would tidy this.
- **No-code automation** (`base_automation`): "on create, email X" —
  the workflow engine covers state machines; rule-based automation
  is an ecosystem-stage feature.
- **Dashboards** (`board`): user report builder partially covers;
  a composer is post-view-engine work.
- **Computed/onchange field runtime**: arrives with the form engine.

## Verdict

**The core is ready to build modules on** — the kernel guarantees
(tenancy, audit, policy, jobs, files, reports, portal) are at or
beyond Odoo's framework, and the operational story (CI, smoke,
DR drill) exceeds what Odoo ships. What is *not* yet at parity is
module-author ergonomics: the view layer.

Recommendation: build **gap #1 (form engine + registry unification)**
before or alongside the first module phase — every hand-written form
is rework once it exists. Gaps #2 and #3 are small enough to ride the
module's gap log. Everything else waits for real demand.
