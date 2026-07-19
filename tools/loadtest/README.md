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

### Honest gaps

- **Search does not yet scale.** The list search ORs `ILIKE '%term%'` across several
  columns *including a JOINed one* (`co.name`). A leading-wildcard `ILIKE` needs a
  `pg_trgm` GIN index, and one unindexed OR branch forces a full seq scan of the
  whole set (**~375 ms**, and it times out under load). Making search fast means: an
  **expression** trigram index per searchable base column — `gin ((COALESCE(col::text,''))
  gin_trgm_ops)` to match the framework's exact search predicate — *and* a decision on
  the JOINed `co.name` column (index `countries.name` or drop it from the search set).
  That "search prefilter" work is the next scalability item.
- **Measure on real hardware + release build for headline numbers.** These are 2-vCPU
  dev-box figures.
