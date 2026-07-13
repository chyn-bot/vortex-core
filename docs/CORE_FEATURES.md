# Vortex Core — Features and How Developers Build on Them

Vortex is a horizontal, multi-tenant, zero-trust ERP **kernel**. The
core ships no industry logic: every domain capability — asset
management, purchasing, a highway-operations vertical, your product —
is a **plugin** that composes the primitives described here. This
document is the map: what the core guarantees, and what a developer
reaches for to get real work done in few lines.

The model is deliberately SAP-like: the kernel is closed and owned by
the platform; developers build against its declared surfaces. Today
those surfaces are two:

1. **In-process plugins** (`vortex-plugin-sdk`) — Rust crates
   implementing the `Plugin` trait, compiled into the host. This is
   how first-party and partner verticals are built.
2. **External apps** — any language, over the public REST API
   (`/api/v1` + scoped bearer tokens), signed webhooks, and the mobile
   auth endpoints. No access to core internals at all.

---

## 1. The kernel: what every plugin inherits for free

These are not features a plugin *uses* so much as guarantees it
*stands on*. They apply to every request before plugin code runs.

### Multi-tenancy
Each tenant is a separate PostgreSQL database, provisioned from the
master registry ("Update Apps List" / `vortex db migrate`). The auth
middleware resolves the tenant per request — session cookie, API
token header, or subdomain (`gaia.vortex.com` → database `gaia`) —
and hands handlers a `DatabaseContext` with the right pool. A global
connection budget stops any tenant from starving the server.

**Leverage:** write handlers as if there were one database. Extract
`Db(db)` and `Extension(db_ctx)`; never construct connection strings.

### Zero-trust security stack
- **WORM audit ledger** — hash-chained, optionally HSM-signed
  (PKCS#11), tamper-evident, verified nightly and exportable as
  JSONL/CEF/LEEF. `vortex audit verify` proves integrity after any
  restore.
- **Cedar policy engine (ABAC)** — every user-initiated action asks
  `state.policy.check(...)`.
- **Sessions & identity** — DB-backed sessions, roles, API tokens
  (hashed, scoped), mobile access/refresh tokens with rotation and
  reuse detection.

**Leverage:** two calls. Gate with `state.policy.check(...)`, record
with `state.audit.log(AuditEntry::new(...))`. Never write to
`audit_log` directly — raw inserts break the hash chain and fail
verification.

### Delivery guarantees
Every push to core is built, unit-tested, route-crawled against a
freshly provisioned tenant (`scripts/smoke.sh` — nothing may 500),
lifecycle-tested and supply-chain-audited. Deployments have a
rehearsed backup/restore procedure (`docs/DISASTER_RECOVERY.md`)
whose drill cryptographically verifies the audit chain post-restore.

---

## 2. The `Plugin` trait: one impl, everything wired

A plugin is a crate with one type implementing `Plugin`
(`vortex_framework::plugin`). Everything is declarative — you state
what you have, the host wires it:

```rust,ignore
impl Plugin for HighwayPlugin {
    fn technical_name(&self) -> &'static str { "highway" }
    fn display_name(&self)   -> &'static str { "Highway Ops" }
    fn version(&self)        -> &'static str { "0.1.0" }
    fn dependencies(&self)   -> Vec<&'static str> { vec!["inventory"] }

    fn routes(&self) -> Router<Arc<AppState>> { /* your axum routes */ }
    fn menu_entries(&self) -> Vec<MenuEntry> { /* sidebar, nestable */ }
    fn migrations(&self) -> Vec<PluginMigration> { /* include_str! SQL */ }
    fn state_machines(&self) -> Vec<StateMachine> { /* workflow defs */ }
    fn scheduled_actions(&self) -> Vec<ScheduledAction> { /* cron work */ }
    fn reports(&self) -> Vec<ReportDef> { /* code-registered reports */ }
    fn translations(&self) -> Vec<Translation> { /* i18n strings */ }
}
```

Registration is two lines in the host (`server.rs` plugin list +
migration registry). Schema is **plugin-owned**: your `migrations/`
directory ships inside your crate and is applied per tenant on
install — never touch the core `migrations/` directory.

The starting recipe: copy `crates/vortex-contacts` (the reference
plugin), rename, and replace the domain.

---

## 3. Application primitives — the toolbox

Each primitive exists because at least two verticals need it. If you
are writing infrastructure inside a plugin, check this list first;
it probably already exists, audited and tested.

### Data & records
| Primitive | What it gives you | Entry point |
|---|---|---|
| ORM + model registry | Typed models; register in `ir_model`/`ir_model_field` and your model becomes visible to the list framework, report builder, and public API | `vortex_orm`, `#[derive(Model)]` |
| Commerce types | Currencies, units of measure, taxes — don't reinvent | `vortex_orm::commerce` |
| Sequences | Per-tenant, per-year document numbering (`SAL/2026/00042`) | sequence service |
| List framework | Declarative list views: pagination (clamped), filters, group-by, aggregates — one definition, full UI | `vortex_framework::list` |
| Form engine | Declare a form once (`FormConfig`/`FormField`) → rendering, widget inference by field kind (text/number/date/checkbox/select/many2one), server-side validation with error round-trip, and type-safe INSERT/UPDATE. Handlers shrink to authorize → save → audit | `vortex_framework::form` |
| Record UX | Field-change tracking (`Tracker`), Odoo-style status bar, rendered audit trail, chatter (messages + secure attachments) on any record | `vortex_framework` + `vortex-chatter` |
| Record duplication | Odoo-style Duplicate on any record: declarative copy spec (skip → DB default, set → override, ` (copy)` suffix, child line tables cloned with counters reset) in one transaction, plus the standard header button and `POST /api/v1/{model}/{id}/duplicate` | `DuplicateSpec`/`ChildCopy`/`duplicate_button` (SDK prelude) |

### Process
| Primitive | What it gives you | Entry point |
|---|---|---|
| Workflow engine | Declared state machines; transitions are policy-gated and audit-logged in one call | `state.workflow.transition(...)` |
| Approval flows | Multi-step sign-off attached to any stage button; inbox UI; no self-approval; applies the stored transition on final approval | `vortex_framework::approval` |
| Scheduler | Recurring actions declared by the plugin, run by one supervisor, admin-visible | `scheduled_actions()` |
| Durable job queue | One-off async work that survives restarts: retries, backoff, dead-letter; tenant-aware | `jobs::enqueue(NewJob::new(kind, payload).for_db(db))` + a registered handler |

### Communication & integration
| Primitive | What it gives you | Entry point |
|---|---|---|
| Mail | Per-tenant SMTP (encrypted credentials), delivery through the job queue | `mail::send_default`, or enqueue `mail.send` |
| Webhooks | Signed (HMAC-SHA256) outbound events with queue-grade delivery guarantees | emit events; endpoints are tenant-configured |
| Public REST API | Generic record CRUD over every registered model, scoped bearer tokens | register your model; API access is automatic |
| Mobile/field auth | Access+refresh tokens designed for offline-first field apps; your plugin's `/api/v1` routes become app-reachable | `vortex_framework::mobile_auth` |
| Public portal | Anonymous routes for public-facing pages — tenant-resolved from the request Host, 404 unless the plugin is installed for that tenant, security headers applied. Convention: `/p/<plugin>` paths. No `AuthUser` exists here | `Plugin::public_routes()` |

### Files & documents
| Primitive | What it gives you | Entry point |
|---|---|---|
| FileStore | Tenant-namespaced blob storage — local disk or any S3-compatible store, chosen by config not code. Store the returned key, never a path | `state.files.put/get/delete(tenant, key, ...)` |
| Attachments | Generic record attachments + chatter uploads with checksums and secure (view-only) documents | `/api/attachments/{model}/{id}` |
| Report builder | End users author tabular reports + sandboxed templates over your registered models — zero plugin code | register models; done |
| PDF engine | HTML → PDF via headless Chromium (optional feature) | `pdf::html_to_pdf` |
| Async report pipeline | Heavy reports queue through the job worker, artifacts land in FileStore, users collect from the Generated Reports inbox with retention | `report_jobs::enqueue_run` |

### Business base modules
Composable, always-on modules that vertical plugins build *with*:

- **Contacts** — the universal partner registry (`res.partner`
  equivalent) and the reference plugin to copy.
- **Inventory** — products, locations, double-entry stock ledger.
  Other modules post moves via `vortex_inventory::service::post_move`.
- **Purchase** — vendors → POs → receipts (posts stock moves).
- **Maintenance/CMMS** — assets, work orders (consume parts through
  inventory), preventive plans via the scheduler. The base the SESB
  EAM vertical specializes.
- **Accounting** — flat CoA, journals, immutable double-entry posting
  (corrections are reversals), AR/AP documents, six financial
  reports. Adopt via `service::create_and_post` /
  `documents::create_invoice` — an invoice in your vertical should be
  an accounting move, not a homemade table.

**The composition rule:** a vertical should be mostly *glue*. SESB
EAM is the proof: it specializes maintenance, consumes inventory,
and inherits workflow/audit/policy/reports — its own code is domain
logic, not infrastructure.

---

## 4. What a handler looks like when you use the stack

```rust,ignore
async fn close_work_order(
    State(state): State<Arc<AppState>>,
    Db(db): Db,                                  // tenant pool, resolved
    Extension(user): Extension<AuthUser>,        // identity + roles
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    // 1. May this user do this? (Cedar)
    state.policy.check(&user, "workorder:close", &id.to_string()).await?;

    // 2. Advance the state machine (audited + gated internally)
    state.workflow.transition(&db, "highway.workorder", id, "close", &user).await?;

    // 3. Domain side-effects through primitives, not hand-rolled SQL
    vortex_inventory::service::post_move(&db, /* parts consumed */).await?;

    // 4. Async follow-ups ride the durable queue
    jobs::enqueue(&state.db, NewJob::new("mail.send", payload)
        .for_db(&db_ctx.db_name)).await?;

    // 5. The WORM ledger records it happened
    state.audit.log(AuditEntry::new(AuditAction::Update, AuditSeverity::Info)
        .with_user(user.id.into()).with_database(&db_ctx.db_name)
        .with_resource("workorder", id.to_string())).await?;

    Json(json!({"ok": true})).into_response()
}
```

Five concerns — authorization, process, domain, async, evidence —
each one line, each inherited.

---

## 5. Rules of the road

1. **Core stays generic.** If your feature names an industry,
   regulator, or geography, it belongs in your plugin.
2. **Never bypass audit or policy** — if it changes state, it goes
   through the gate and onto the ledger.
3. **Own your schema** — plugin migrations live in your crate; core
   tables are read through the primitives, not written directly.
4. **Store keys, not paths** — FileStore keys survive backend
   changes; filesystem paths don't.
5. **`AppState` is the ABI.** Additive changes only; treat it like a
   published interface, because it is one.
6. **If two verticals could want it, propose it for core.** That is
   how inventory, approval flows, the FileStore and the report
   pipeline came to exist.

---

*Deeper dives: `docs/ARCHITECTURE.md` (platform contract, deployment
shapes), `docs/DISASTER_RECOVERY.md` (backup/restore),
`crates/vortex-contacts` (reference plugin),
`crates/vortex-sesb-eam` (a full vertical built this way).*
