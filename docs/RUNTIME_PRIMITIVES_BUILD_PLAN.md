# Vortex Runtime Primitives — Build-to-Parity Plan

**Goal:** complete the five Vortex-native platform components so each stands on its
own as a production-grade, billable equivalent of its incumbent — the greenfield
assumption in the Trinitium/IWK proposals. This is the engineering backlog behind
the "Arbiter / Conduit / Grid / Cascade / Runtime" naming.

## Naming map (marketing name → what it is → incumbent → source of truth)

| Component  | Role                        | Incumbent          | Source files                                                                 | Migrations | Maturity |
|------------|-----------------------------|--------------------|------------------------------------------------------------------------------|------------|----------|
| **Cascade**| Batch / deterministic compute | Spring Batch      | `vortex-framework/src/{batch,assembly,snapshot,trial,batch_admin}.rs`         | 159–162    | ★★★★☆ strong, **unmerged** |
| **Arbiter**| Rules / decision engine     | Zen Engine (GoRules)| `vortex-framework/src/rules.rs`                                              | 162        | ★★★★☆ strong core, no UI, **unmerged** |
| **Conduit**| Event bus / async delivery  | Kafka              | `vortex-framework/src/{jobs,webhooks,report_jobs}.rs`                         | 129–131,134| ★★★☆☆ solid outbox, one-way |
| **Grid**   | In-process cache / hot state| Redis              | `vortex-orm/src/cache.rs`                                                     | —          | ★★☆☆☆ **implemented but not wired** |
| **Runtime**| Scheduling / orchestration  | K8s cron / Airflow | `vortex-framework/src/scheduler/{mod,action,storage,supervisor}.rs` + `jobs.rs::JobWorker` | 118 | ★★★☆☆ interval-only |

### Branch reality (do this first)
- **Cascade + Arbiter** live on `feat/batch-processing-core` only. They are **not**
  on `master` and **not** in `security/type-a-hardening`'s `lib.rs`. Step 0 is to
  land that branch (or rebase these files forward) so the modules are wired.
- **Conduit + Runtime + Grid** are on `master`/current.
- Verify wiring after merge: `grep -nE 'mod (batch|rules|assembly|snapshot|trial)' crates/vortex-framework/src/lib.rs`

---

## Cascade (batch) — ★★★★☆ → complete the last mile

**Have:** run lifecycle (`create_run`/`add_items`/`start`), chunked dispatch over the
durable queue, fail-item isolation, idempotent restart (conditional `WHERE status='pending'`),
trial/live propagation, snapshot pairing, calculator-chain assembly, admin UI
(`/batch/runs*`), exception retry. Schema `batch_run` + `batch_run_item` (159), idempotency
key (160), snapshot (161).

**To complete:**
1. **Throughput / parallelism** — chunks currently serialize per worker; confirm N
   concurrent `batch.chunk` jobs actually run in parallel and add a per-run concurrency
   cap so one run can't starve the queue. *Accept:* 400k-item run finishes within target
   wall-clock on 4 workers; other job kinds still drain.
2. **Cancellation** — `status='cancelled'` exists in schema but wire a `POST /batch/runs/{id}/cancel`
   that stops dispatching remaining chunks and lets in-flight items finish. *Accept:* cancel
   mid-run leaves no orphaned `pending` chunks enqueued.
3. **Chunk-level retry policy** — today a chunk-job failure retries the whole chunk via the
   job queue; ensure item idempotency makes that safe (it should) and surface chunk vs item
   failures distinctly in the admin UI.
4. **Metrics** — expose items/sec, ETA, exception-rate on the run page (already has counts;
   add rate + projection).
5. **Run history retention** — a sweep to archive/prune old `batch_run_item` rows (400k/run
   accumulates fast).
6. **Tests** — crash-resume test (kill mid-chunk, restart, assert no double-processing);
   trial-vs-live parity test (identical line output, side-effects suppressed).

---

## Arbiter (rules) — ★★★★☆ → give it an authoring surface + richer operators

**Have:** pure evaluator (`Condition` And/Or/Not/Eq/Gt/Gte/Lt/Lte/In + `Amount` Fixed/PercentOf),
immutable versioning (`create_version`/`add_rule`/`publish`/`load`/`latest_published`/`load_version`),
per-adjustment provenance (which rule+version fired, incl. no-ops), JSONB storage. Schema (162).

**To complete:**
1. **Authoring UI** — the biggest gap. Analyst-facing rule-set editor: list versions, add/edit
   rules (condition builder + amount formula) on a *draft*, publish (freezes). Read-only view of
   published versions. *Accept:* an analyst adds a rebate rule and publishes without a code change.
2. **Operator coverage** — add the operators real tariffs need: `Between`, `NotIn`, string
   `StartsWith`/`Contains`, null checks, and date comparisons. Extend `Amount` with `Tiered`
   (bracketed/block tariff — the classic utility case) and `PerUnit(qty_field)`. *Accept:* a
   3-tier block tariff is expressible as data.
3. **Decision-table form** — optional UI sugar: render a set of flat `Eq` rules as a grid
   (this is what "Zen Engine" markets). Compiles down to the existing `Condition`/`Amount`.
4. **Simulation / test harness** — a "test this version against sample input" panel that shows
   which rules fire and the resulting adjustments, using the pure `evaluate()` (no DB writes).
5. **Decision log table** — optional durable record of `(rule_version, input_hash, adjustments)`
   for court-defensible replay beyond what the consuming record already stores.
6. **Export/import** — versioned rule-set JSON export for promotion across environments (mirrors
   Blueprint export). *Accept:* export from staging, import to prod, byte-identical evaluation.

---

## Conduit (jobs + webhooks) — ★★★☆☆ → close the loop + latency + ops

**Have:** durable `ir_job` queue (`FOR UPDATE SKIP LOCKED`, priority, exponential backoff,
dead-letter, per-job `db_name` for tenant routing), outbound HMAC-SHA256 webhooks over that
queue (transactional-outbox pattern), delivery attempt log, async report pipeline. Schema 129–131,134.

**To complete:**
1. **Low-latency dispatch** — worker polls every 5s. Add Postgres `LISTEN/NOTIFY` on enqueue so
   jobs start in ms, not seconds, while keeping the poll as a safety net. *Accept:* enqueue→start
   p50 < 200ms.
2. **Inbound webhooks / event ingestion** — Conduit is one-way (outbound only). Add a signed
   inbound endpoint (`POST /hooks/{source}`) that verifies HMAC and enqueues a normalized event —
   the Kafka-consumer half. *Accept:* an external system pushes an event that a handler consumes.
3. **Subscription catalog + replay** — a first-class registry of event types (today `emit` takes a
   free string) and a replay action: re-deliver events in a time range to an endpoint. *Accept:*
   re-drive a day of `record.updated` to a recovered consumer.
4. **Ordering / partition keys** — optional per-key FIFO (e.g. all events for one account in order)
   via a `partition_key` column and per-key serialization. Kafka's headline feature; needed for
   any consumer that can't tolerate reorder.
5. **Ops UI** — dead-letter queue viewer + requeue, endpoint delivery health, per-endpoint
   pause/resume. (`recent_deliveries` exists; build the page.)
6. **Poison-message quarantine** — surface `status='dead'` jobs in the UI with the last error and a
   one-click requeue after fix (mirrors Cascade's exception queue).

---

## Grid (record cache) — ★★☆☆☆ → **wire it, then make it multi-instance-safe**

**Have:** a complete `RecordCache` (TTL, LRU-ish accessed/hits metadata, `invalidate`/
`invalidate_model`/`invalidate_company`, `CacheStats` hit-rate, `DependencyTracker`, `cleanup`).
**Critical gap:** it is **not wired into the read/write path** — `make_cache_key` is only
referenced in unit tests; nothing calls `.get()`/`.put()` on live queries. It is a shelf part.

**To complete:**
1. **Wire into the ORM** — put a `RecordCache` on `AppState`, consult it in the model `get`/`load`
   path, populate on miss, and **invalidate on every save/update/delete**. Start read-through on
   single-record fetch only (safest). *Accept:* hot record served from cache; a save is reflected
   on next read (no stale).
2. **Cross-process invalidation** — the cache is process-local; a second app instance won't see
   another's writes. Broadcast invalidations via Postgres `LISTEN/NOTIFY` (`cache_invalidate`
   channel carrying model+pk). *Accept:* write on instance A invalidates instance B within one
   notify round-trip. **Do not ship multi-instance without this** — it's a correctness bug, not a
   perf tuning.
3. **Config + safety** — per-model opt-in (never cache audit/session tables), max-size eviction,
   and a global kill-switch env var. Default **off** until proven.
4. **Observability** — a `/admin/cache/stats` page (hit rate, size, evictions) from existing
   `CacheStats`.
5. **Scope honesty** — this is an in-process cache, not a Redis cluster. If a shared/distributed
   store is ever required (cross-node session state, rate-limit counters), that's a separate
   component; document Grid's boundary so the proposal claim stays truthful.

---

## Runtime (scheduler) — ★★★☆☆ → the module's own gap list

**Have:** persistent `scheduled_actions` (migration 118), `FOR UPDATE SKIP LOCKED` claim, a single
supervisor polling every `poll_interval`, handler map by action code, `Plugin::scheduled_actions()`.
The module **documents its own cuts** (see `scheduler/mod.rs` "does NOT provide yet").

**To complete (verbatim from the module's own list + ops):**
1. **Cron expressions** — only `Schedule::Every(interval)` today. Add cron-string parsing
   (`cron` crate) → `Schedule::Cron(String)`. *Accept:* "0 2 * * *" runs at 02:00.
2. **Manual run-now** — no imperative trigger today. Add `POST /runtime/actions/{code}/run`.
3. **Run history + recovery sweep** — currently at-most-once: a crash between `next_call` advance and
   handler completion loses the run. Add a `scheduled_run` history table + a startup recovery sweep
   that re-dispatches runs that were claimed-but-not-completed. *Accept:* kill mid-run → run replays
   on restart.
4. **Retry with backoff** — a failed run just waits for the next tick. Route failures through the
   Conduit job queue (which already has backoff + dead-letter) instead of the naive tick.
5. **Per-tenant schedules** — actions are system-wide; wire multi-DB-per-process scheduling so each
   tenant DB's `scheduled_actions` are polled. (Trivial under one-tenant-per-DB; needed for shared
   process.)
6. **Admin UI** — actions are SQL-only today. List/toggle/edit/run-now + last-result. *Accept:* an
   admin disables a nightly job from the UI.

---

## Suggested sequencing

1. **Step 0 — land `feat/batch-processing-core`** (Cascade + Arbiter) to master and confirm
   `lib.rs` wiring. Nothing below matters until these compile on the working branch.
2. **Grid wiring (item 1+2)** — highest correctness risk and smallest surface; do it first so the
   multi-instance story is honest.
3. **Runtime cron + run-now + recovery** — unblocks real scheduled billing cycles for IWK.
4. **Conduit LISTEN/NOTIFY + inbound + DLQ UI** — the parity-defining features.
5. **Arbiter authoring UI + tiered amounts** — the analyst-facing win; also the most demo-able.
6. **Cascade last-mile** (cancel, metrics, retention) — polish on an already-strong base.

## Cross-cutting acceptance
- Every component gets an **admin/ops surface** (parity claims are judged on operability, not just
  the engine).
- Every distributed claim is **multi-instance-tested** (two app processes on one DB).
- Update proposal docs (`vortex-core-module-spec`, IP schedule) only after each item actually ships —
  keep the greenfield claim defensible.

## Kickoff prompt for the new session
> "Build the Vortex runtime primitives per `docs/RUNTIME_PRIMITIVES_BUILD_PLAN.md`. Start with Step 0
> (land feat/batch-processing-core and confirm lib.rs wiring), then Grid wiring items 1–2. Work on a
> branch off master."
