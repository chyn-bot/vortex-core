# vortex-loadtest

A self-contained HTTP load harness for Vortex Core. Ramps concurrency against a
running server and reports latency percentiles (p50/p90/p95/p99/max), throughput
(req/s) and error rate at each level — the "how many concurrent users" curve
behind any scalability claim. No external tool (k6/wrk) required; it's just
tokio + reqwest, so it runs anywhere the server does, including the target
instance type.

It's a **standalone crate** (detached from the workspace) so it never affects the
product build.

## Build & run

```sh
cd tools/loadtest
cargo build --release

# Public endpoint (no auth) — raw request-handling capacity:
./target/release/vortex-loadtest \
  --url http://127.0.0.1:3000 --path /health \
  --concurrency 1,10,50,100,200 --duration 5

# Authenticated endpoint — logs in, carries the session cookie:
./target/release/vortex-loadtest \
  --url http://127.0.0.1:3010 --path "/contacts?search=smith" \
  --user admin --pass 'secret' --database remicle \
  --concurrency 1,5,10,25,50 --duration 5 --warmup 2
```

Flags: `--url`, `--path`, `--concurrency`/`-c` (comma list), `--duration`/`-d`
(seconds per level), `--warmup`, `--user`, `--pass`, `--database`.

## Reading the results — and their limits

**Measure on the actual target hardware.** A number from a small dev box does not
transfer to an m6.large. The harness is the reproducible *method*; the headline
number must be produced on the instance type being sold.

**Match the build.** A `cargo build --release` server is dramatically faster than
the default `debug` build. Always load-test a release binary.

**Pick a representative endpoint.** `/health` measures only the HTTP layer (no DB).
A real list/search endpoint measures the whole stack (auth → policy → query →
render) and is what actually bounds concurrent users.

## Reference measurements (2-vCPU dev box, contacts @ 200k rows)

The contacts **browse**, tuned step by step, shows what each fix is worth:

| Configuration | req/s (c=1 … c=100) | p50 @ c=1 |
|---|---|---|
| debug, no index, exact `COUNT(*)` | ~5 … 14 | 200 ms |
| release, no index, `COUNT(*)` | ~7 … 26 | 141 ms |
| **release, `+ estimate_count() + index(name,id)`** | **~394 … ~1,000** | **2 ms** |

Two changes carried that ~40× throughput / ~64× latency improvement:

- **`ListConfig::estimate_count()`** — replaces the exact `COUNT(*)` over the JOIN
  (measured **59 ms**) with a `pg_class.reltuples` estimate (**1.8 ms**).
- **An index on `(name, id)`** matching `ORDER BY name, id` — turns a top-N
  heapsort over the whole table (**92 ms**) into an Index Scan (**1.1 ms**). Shipped
  as contacts migration `008_browse_index`.

At the query level, deep pagination is likewise proven: on 200k rows with that
index, a deep `OFFSET 175000` reads 175,025 rows (**~93 ms**) while a keyset seek to
the same depth is **~0.18 ms** (`ListConfig::keyset()`).

### Search (also fixed)

The list search is a leading-wildcard `ILIKE '%term%'`, which a btree index can't
serve; and it originally ORed across several columns *including a JOINed one*
(`co.name`), so one unindexed branch forced a full seq scan (**~375 ms**, timing out
under load). Two changes fixed it:

- **`ListConfig::search_prefilter()`** rewrites search to `pk IN (SELECT id FROM
  table WHERE <base-column ILIKEs>)` — the subquery runs on the base table so
  trigram indexes apply, and the JOINed `co.name` is excluded from the fast path
  (search it via a filter instead).
- **Expression `pg_trgm` GIN indexes** on `COALESCE(col::text,'')` for each base
  searchable column (contacts migration `009_search_indexes`), matching the
  prefilter's exact predicate.

| contacts search @ 200k rows | req/s (c=1…100) | p50 @ c=1 |
|---|---|---|
| before (inline OR, seq scan) | ~1 … 2 (times out ≥ c=50) | 662 ms |
| **after (prefilter + trigram)** | **~181 … ~366** | **5 ms** |

### Note

Measure on real hardware + a release build for headline numbers — these are 2-vCPU
dev-box figures.
