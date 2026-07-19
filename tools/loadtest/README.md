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

## Reference measurements (2-vCPU dev box, **debug** build — indicative only)

| Endpoint | Throughput ceiling | Latency behaviour |
|---|---|---|
| `/health` (no DB) | ~2,300 req/s, 0 errors | p50 0.7 ms → 85 ms at c=200 |
| `/contacts` list, 200k rows (JOIN + `COUNT(*)`, **no keyset**) | ~5–14 req/s | p50 200 ms → 6.7 s at c=50 |

The second row is the honest cautionary data point: the current contacts list runs
a `COUNT(*)` over a 200k-row JOIN on every request, which is O(rows) and does not
scale — this is precisely the path keyset pagination + a count estimate are meant
to replace. At the query level that fix is already proven:

```
-- 200k rows, index on (name, id):
Deep OFFSET (175000):  ~93 ms   (Index Only Scan reads 175,025 rows)
Keyset seek to depth:  ~0.18 ms (pk-index boundary lookup + ROW(name,id) > ROW(...))
```

**Bottom line:** the list framework *has* keyset (see `ListConfig::keyset()`), and
it's O(log n) at any depth — but no high-volume production list is wired to it yet
(contacts is blocked by its JOIN). Wiring keyset + a `(sort_col, id)` index into a
plain-table list, on a release build and real hardware, is the step that turns
these component numbers into a defensible end-to-end "N concurrent users" figure.
