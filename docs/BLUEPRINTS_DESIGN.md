# Vortex Blueprints — Design Plan

**Status:** Draft / proposal · **Author:** design session 2026-07-13 · **Depends on:** §2 integrity seam (shipped, `348ae8e`), the low-code layer (`ir_model` registry, custom fields, computed fields, automation rules, saved views).

---

## 1. What this is

A **Blueprint** is a user-defined, governed model — its fields, relations, and views — created from the browser with **no deploy**, from which real, first-class records are produced at runtime.

Today an admin can extend *existing compiled models* (custom fields, computed fields, automation) with no deploy. What they still cannot do is create a *whole new model* and lay out its form/list from the UI. Blueprints closes that gap. It is the single capability that turns Vortex from "a framework with a strong generic layer" into a **no-code application platform** — the equivalent of Odoo Studio / Frappe Doctype.

### The thesis: parity by leverage, lead by governance

- **Parity is nearly free.** After §1 (`derive(Model)` → `ir_model` as the single source of truth) and §2 (the generic layer is now contract-solid), the generic list/form/kanban/graph/pivot/calendar layer, saved views, custom fields, computed fields, automation, REST API, and webhooks **all read the registry**. A Blueprint is just another `ir_model` row backed by a real table — so the entire existing stack works on it with near-zero per-feature changes. That is the multiplier no other item on the roadmap has.
- **The lead is the governance.** Odoo Studio and Frappe Doctype let you build models with *no governance*. Vortex builds the same thing **on top of the WORM audit ledger and the Cedar ABAC policy engine**: every blueprint create/alter/delete is hash-chained, signed, and policy-gated; schema changes can require approval before they go live. A *governed* no-code builder is genuinely ahead of theirs in the regulated-industry niche we already own. **We do not out-feature them on breadth; we out-govern them on the feature they're proudest of.**

## 2. Goals / Non-goals

**Goals**
- Create/alter/delete a model (a Blueprint) and its fields from the UI, no deploy, per tenant.
- Blueprint records are first-class: real tables, real FKs, real indexes — indistinguishable from compiled models to the generic layer, REST API, reporting, automation, and webhooks.
- Every schema change is audited (WORM) and policy-gated (Cedar); schema changes can require approval.
- Blueprints are portable: exportable as a manifest for dev→prod promotion, and (later) as the seed of a compiled plugin crate.

**Non-goals (explicitly deferred)**
- **Arbitrary user code** (server/client scripts). Blueprints are *declarative*. A code escape hatch, if ever, is a separate WASM-sandbox effort.
- **Dynamic plugin loading / marketplace** (the standing Critical). Blueprints are the on-ramp toward it, not a substitute — see Phase 5.
- **Website/CMS/eCommerce.** Separate track (the interactive-portal roadmap item).

## 3. The central decision: storage strategy

Two options for where blueprint records live:

| | **A. Generated physical tables (recommended)** | **B. JSONB-per-record** |
|---|---|---|
| Shape | One real table `x_<blueprint>` per Blueprint; one real column per field | One `blueprint_record(data JSONB)` table for all |
| Generic layer | **Works unchanged** — it already speaks SQL over real tables (`ir_model.table_name`) | Every list/pivot/graph query needs JSONB special-casing |
| Typing / indexes / FKs | Real column types, real indexes, real FK constraints to compiled models | Weak typing; GIN/expression indexes; app-level integrity only |
| Reporting / pivot / performance | First-class, no special path | Slower, awkward aggregation |
| Risk | **Dynamic DDL** from user input — must be tightly controlled | No runtime DDL (safer on its face) |
| Precedent | Frappe (one table per Doctype), Odoo (real columns via `ir.model`) | Some headless CMSs |

**Recommendation: A, generated physical tables.** The dynamic-DDL risk is real but *bounded and industry-proven*; the upside is that we inherit the entire generic-layer-over-real-tables machinery we already built and hardened, with correct typing, indexing, and referential integrity. JSONB would make the strong parts of the system (pivot, graph, reporting, FK integrity) worse to reach parity — the wrong trade.

**How the DDL risk is contained (zero-trust posture):**
- All DDL flows through **one service** (`blueprint::ddl`) that *composes* statements from validated metadata — the user never supplies SQL.
- Every identifier passes `validate_identifier()`; generated tables/columns carry an **`x_` prefix** (Odoo convention) to namespace away from compiled schema; a reserved-name blocklist applies.
- Field types come from a **fixed vocabulary** (the `ir_model_field.field_type` CHECK set).
- DDL runs in a transaction, is **recorded in a per-tenant `blueprint_ddl_log`** (so blueprint schema is reproducible/verifiable, exactly as `vortex_migrations` does for plugin schema — this closes the new drift surface before it opens), and emits a WORM audit event.
- **Per-tenant quotas** (max blueprints, max fields/blueprint) prevent a schema-bomb DoS.

> An optional JSONB `x_extra` overflow column on each generated table lets the *existing* custom-fields layer bolt ad-hoc fields onto a Blueprint without an ALTER — best of both, added later if wanted.

## 4. Registry integration — the leverage point

A Blueprint **is** registry rows, not a parallel system:

- An `ir_model` row with a new flag `source = 'blueprint'` (vs `'derived'` for `derive(Model)`), `table_name = 'x_<name>'`, `is_virtual = true`.
- Its fields are `ir_model_field` rows with `source = 'blueprint'`.

Consequences (all **free**, because these subsystems already read the registry):
- Generic **list / form / kanban / graph / pivot / calendar** render it.
- **REST API** (`/api/v1/{model}`) exposes CRUD over it.
- **Webhooks** fire `record.created/updated/deleted`.
- **Automation rules**, **computed/related fields**, **custom fields**, **saved views**, **many2one typeahead** all apply.

**One required change to code shipped this session:** the boot-time registry sync + prune (`registry_sync::sync_one`) currently owns `source='derived'` rows. It must **only prune `source='derived'`** and never touch `'blueprint'` or `'custom'` rows. (Today it keys on `is_custom=false`; migrate that to the explicit `source` enum so the three kinds — derived / custom / blueprint — are unambiguous.)

## 5. Governance integration — where we pass Odoo/Frappe

- **Audit (WORM):** every `blueprint.create / alter_field / rename / delete` calls `state.audit.log()`. Schema changes are the highest-value audit events in an ERP; making them tamper-evident is a capability neither rival has.
- **Policy (Cedar):** new action schema — `Blueprint::{Create, AlterField, Delete, Publish}` — gated by `state.policy.check()`. E.g. "only the `data-architect` role may create Blueprints, and only within their own company."
- **Approval (reuse the approval-workflow primitive):** a Blueprint change can be configured to require multi-step sign-off *before the DDL executes*. Draft → pending → approved → applied. This is "governed no-code": the schema of production is never changed without an approved, audited plan.
- **Versioning:** a `blueprint_version` history captures each definition revision (who, when, diff), enabling rollback and a schema-history view.

## 6. Data model (new tables)

```
-- Migration 1xx_blueprints (core)

-- Registry flags (extend existing tables)
ALTER TABLE ir_model       ADD COLUMN source VARCHAR(16) NOT NULL DEFAULT 'derived',  -- derived|blueprint
                           ADD COLUMN is_virtual BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE ir_model_field ADD COLUMN source VARCHAR(16) NOT NULL DEFAULT 'derived';  -- derived|custom|blueprint
-- backfill: is_custom=true -> source='custom'; then the prune keys on source='derived'

-- Blueprint definition (metadata beyond ir_model)
CREATE TABLE blueprint (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    model_id      UUID NOT NULL REFERENCES ir_model(id) ON DELETE CASCADE,
    company_id    UUID,                    -- owning tenant company (row scoping)
    status        VARCHAR(16) NOT NULL DEFAULT 'draft',   -- draft|active|archived
    icon          VARCHAR(64),
    description    TEXT,
    created_by    UUID NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_blueprint_model UNIQUE (model_id)
);

-- Immutable-ish revision history of the definition (for rollback + audit view)
CREATE TABLE blueprint_version (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    blueprint_id  UUID NOT NULL REFERENCES blueprint(id) ON DELETE CASCADE,
    version       INTEGER NOT NULL,
    definition    JSONB NOT NULL,          -- full field/view snapshot
    applied_by    UUID NOT NULL,
    applied_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_blueprint_version UNIQUE (blueprint_id, version)
);

-- Per-tenant DDL ledger — makes generated schema reproducible/verifiable,
-- mirrors vortex_migrations so Blueprints don't reopen the drift surface.
CREATE TABLE blueprint_ddl_log (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    blueprint_id  UUID NOT NULL REFERENCES blueprint(id) ON DELETE CASCADE,
    statement     TEXT NOT NULL,           -- the composed DDL we ran
    applied_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Each generated record table (created at runtime by the DDL service):
-- CREATE TABLE x_<name> (
--   id UUID PK, company_id UUID, active BOOLEAN DEFAULT true,
--   created_at TIMESTAMPTZ, updated_at TIMESTAMPTZ,
--   <one real column per blueprint field>
-- );
```

View/layout persistence reuses the existing `saved_views` + custom-field-position machinery — no new table for layouts.

## 7. Phase plan

Each phase is independently shippable and demoable. Phases 1–2 already produce a working no-code app.

**Phase 0 — Foundations (no UI).** Decision locked (physical tables). Migration: `source`/`is_virtual` on the registry (+ backfill `is_custom`→`source='custom'`), `blueprint` / `blueprint_version` / `blueprint_ddl_log` tables. The `blueprint::ddl` service skeleton: identifier validation, `x_` prefixing, reserved-name blocklist, transactional apply, DDL-log write, audit hook. Update `registry_sync` prune to key on `source='derived'`. Unit tests for the DDL composer + validation.

**Phase 1 — Model & field CRUD (the "aha").** Governed service + minimal admin UI to: create a Blueprint (generates `x_<name>` with the standard system columns), add/remove/rename fields (ALTER via the DDL service), from the fixed type vocabulary. Every op audited + Cedar-gated. **Because the model is now in the registry, records are immediately CRUD-able through the *existing* generic list/form** — create a model, get a working app in one step.

**Phase 2 — View & layout designer.** Form layout (field order, groups, tabs) and list columns, persisted like saved views. Kanban/pivot/graph/calendar already work generically — expose their config to Blueprints.

**Phase 3 — Relations & rich fields.** many2one to compiled models *and* other Blueprints (reuse `FieldKind::Many2One` + typeahead + signed `LookupSource`), one2many/many2many, selection, computed/related (reuse `computed_fields`), defaults, required/unique constraints — enforced as real DB constraints.

**Phase 4 — Governance depth (the lead).** Blueprint versioning + change **approval** before DDL (reuse approval workflow), blueprint-scoped Cedar policies, per-tenant quotas, and a schema-history / audit view. This is the increment Odoo/Frappe cannot match.

**Phase 5 — Portability & the distribution on-ramp.** Export/import a Blueprint as a **signed manifest** (dev→prod promotion; reuses `vortex_security::crypto`). Then a **"scaffold a plugin crate from this Blueprint"** generator (reuse the existing `vortex scaffold plugin`): a Blueprint that has proven itself as data can be promoted to compiled code. This is the deliberate bridge toward the parked Critical (dynamic loading) — Blueprints de-risk it by letting the model exist and be validated *before* anyone commits to shipping code.

## 8. What we reuse (net-new surface is small)

| Capability | Source | Status |
|---|---|---|
| Model/field registry | `ir_model` / `ir_model_field` (§1) | reuse |
| Generic list/form/kanban/graph/pivot/calendar | server.rs generic views (§2, now contract-solid) | reuse |
| Field-position / layout persistence | custom-field-position, `saved_views` | reuse |
| many2one typeahead | `LookupSource` / `/api/lookup` | reuse |
| Computed/related fields | `computed_fields` | reuse |
| Automation on records | automation rules | reuse |
| REST API + webhooks | `vortex_framework::api` / `webhooks` | reuse |
| Audit | `state.audit.log()` WORM | reuse |
| Policy | Cedar `state.policy.check()` | new action schema |
| Approval before schema change | approval workflow | reuse |
| Plugin scaffold (Phase 5) | `vortex scaffold plugin` | reuse |
| **Net-new** | DDL service, blueprint tables, builder UI, prune `source` change | **build** |

## 9. Risks & open questions

- **Dynamic DDL safety** — mitigated by the single-service + validate_identifier + fixed vocabulary + `x_` prefix + transactional + audited design. Highest-scrutiny code; belongs in `vortex-orm` with heavy tests and a `#[deny]` on any string-interpolated identifier that didn't pass validation.
- **Per-tenant schema drift (new surface)** — Blueprint DDL is per-tenant and runtime. `blueprint_ddl_log` makes it reproducible/verifiable; a `vortex db verify-blueprints` check (analogous to the migration integrity work in §2 #4) should confirm each tenant's `x_` tables match their definitions.
- **Rename/alter semantics** — renaming a field is `ALTER … RENAME COLUMN` + registry update; a *type change* may need a data migration or be disallowed (start: additive-only + rename + drop; type-change deferred).
- **Referential integrity across kinds** — a Blueprint FK to a compiled model is a real constraint; dropping a compiled model that a Blueprint references must be handled (compiled models rarely drop, but the case exists).
- **Upgrade interaction** — if a future compiled plugin wants a table name a Blueprint already took: the `x_` prefix reserves the blueprint namespace, so collisions are structurally prevented.
- **Quotas & multi-company** — defaults TBD; `company_id` row-scoping consistent with all models.

## 10. Recommendation

Build Phases 0–2 first as one coherent milestone — that alone delivers a **governed no-code app builder** (create a model, get an audited, policy-gated, fully-featured CRUD app with pivot/graph/kanban/calendar) and is the strongest single answer to "why Vortex over Odoo/Frappe" for a regulated buyer. Phases 3–4 deepen the lead; Phase 5 sets up the endgame (distribution) without committing to it prematurely.
