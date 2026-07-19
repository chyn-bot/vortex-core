//! Vortex Core — standalone HTTP load harness.
//!
//! Ramps concurrency against a running server and reports latency percentiles
//! (p50/p90/p95/p99/max), throughput (req/s) and error rate at each level — the
//! "how many concurrent users" curve behind the scalability claims. Self-
//! contained (tokio + reqwest, no external load tool), so it runs anywhere the
//! server does, including the target instance type.
//!
//! It optionally logs in first (`POST /auth/login`, form-encoded) and carries
//! the session cookie, so it can drive authenticated endpoints (a real list
//! page), not just the public health check.
//!
//! Usage:
//!   vortex-loadtest --url http://127.0.0.1:3010 --path /health \
//!       --concurrency 1,10,50,100,200 --duration 5
//!
//!   vortex-loadtest --url http://127.0.0.1:3010 --path "/contacts?search=smith" \
//!       --user admin --pass 'secret' --database remicle \
//!       --concurrency 10,50,100,200,400 --duration 8
//!
//! Note: measure on the actual target hardware for headline numbers — a number
//! from a 2-vCPU dev box does not transfer to an m6.large.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

struct Args {
    url: String,
    path: String,
    concurrency: Vec<usize>,
    duration: u64,
    warmup: u64,
    user: Option<String>,
    pass: Option<String>,
    database: Option<String>,
}

fn parse_args() -> Args {
    let mut a = Args {
        url: "http://127.0.0.1:3000".into(),
        path: "/health".into(),
        concurrency: vec![1, 10, 50, 100],
        duration: 5,
        warmup: 1,
        user: None,
        pass: None,
        database: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut val = || it.next().unwrap_or_default();
        match k.as_str() {
            "--url" => a.url = val().trim_end_matches('/').to_string(),
            "--path" => a.path = val(),
            "--concurrency" | "-c" => {
                a.concurrency = val()
                    .split(',')
                    .filter_map(|s| s.trim().parse().ok())
                    .filter(|n| *n > 0)
                    .collect();
            }
            "--duration" | "-d" => a.duration = val().parse().unwrap_or(5),
            "--warmup" => a.warmup = val().parse().unwrap_or(1),
            "--user" => a.user = Some(val()),
            "--pass" => a.pass = Some(val()),
            "--database" => a.database = Some(val()),
            "--help" | "-h" => {
                eprintln!("{}", include_str!("main.rs").lines().take(24).collect::<Vec<_>>().join("\n"));
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown arg: {other}");
                std::process::exit(2);
            }
        }
    }
    if a.concurrency.is_empty() {
        a.concurrency = vec![1, 10, 50, 100];
    }
    a
}

/// Percentile (nearest-rank) from a sorted-ascending slice of microsecond latencies.
fn pct(sorted: &[u64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[idx] as f64 / 1000.0 // → milliseconds
}

struct Level {
    conc: usize,
    reqs: u64,
    errors: u64,
    rps: f64,
    lat_ms: Vec<u64>, // per-request latencies in micros
}

async fn run_level(client: Arc<reqwest::Client>, target: Arc<String>, conc: usize, dur: u64) -> Level {
    let deadline = Instant::now() + Duration::from_secs(dur);
    let mut handles = Vec::with_capacity(conc);
    for _ in 0..conc {
        let client = client.clone();
        let target = target.clone();
        handles.push(tokio::spawn(async move {
            let mut lat: Vec<u64> = Vec::new();
            let mut errors: u64 = 0;
            while Instant::now() < deadline {
                let t0 = Instant::now();
                match client.get(target.as_str()).send().await {
                    Ok(resp) => {
                        // Drain the body so keep-alive works and timing includes transfer.
                        let ok = resp.status().is_success();
                        let _ = resp.bytes().await;
                        if !ok {
                            errors += 1;
                        }
                    }
                    Err(_) => errors += 1,
                }
                lat.push(t0.elapsed().as_micros() as u64);
            }
            (lat, errors)
        }));
    }
    let mut lat_ms = Vec::new();
    let mut errors = 0u64;
    for h in handles {
        if let Ok((mut l, e)) = h.await {
            lat_ms.append(&mut l);
            errors += e;
        }
    }
    let reqs = lat_ms.len() as u64;
    Level {
        conc,
        reqs,
        errors,
        rps: reqs as f64 / dur as f64,
        lat_ms,
    }
}

#[tokio::main]
async fn main() {
    let args = parse_args();
    let target = Arc::new(format!("{}{}", args.url, args.path));

    let client = reqwest::Client::builder()
        .cookie_store(true)
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(1000)
        .build()
        .expect("build client");

    // Optional login so authenticated endpoints can be driven.
    if let (Some(u), Some(p)) = (&args.user, &args.pass) {
        let mut form = vec![("username", u.clone()), ("password", p.clone())];
        if let Some(db) = &args.database {
            form.push(("database", db.clone()));
        }
        let login_url = format!("{}/auth/login", args.url);
        match client.post(&login_url).form(&form).send().await {
            Ok(r) => eprintln!("login {} → {}", login_url, r.status()),
            Err(e) => {
                eprintln!("login failed: {e}");
                std::process::exit(1);
            }
        }
    }

    let client = Arc::new(client);

    eprintln!(
        "target: {}   duration/level: {}s   warmup: {}s",
        target, args.duration, args.warmup
    );
    println!(
        "{:>6}  {:>9}  {:>9}  {:>7}  {:>8}  {:>8}  {:>8}  {:>8}  {:>9}",
        "conc", "reqs", "req/s", "errors", "p50 ms", "p90 ms", "p95 ms", "p99 ms", "max ms"
    );
    println!("{}", "-".repeat(86));

    for &conc in &args.concurrency {
        if args.warmup > 0 {
            let _ = run_level(client.clone(), target.clone(), conc, args.warmup).await;
        }
        let mut lvl = run_level(client.clone(), target.clone(), conc, args.duration).await;
        lvl.lat_ms.sort_unstable();
        println!(
            "{:>6}  {:>9}  {:>9.0}  {:>7}  {:>8.2}  {:>8.2}  {:>8.2}  {:>8.2}  {:>9.2}",
            lvl.conc,
            lvl.reqs,
            lvl.rps,
            lvl.errors,
            pct(&lvl.lat_ms, 50.0),
            pct(&lvl.lat_ms, 90.0),
            pct(&lvl.lat_ms, 95.0),
            pct(&lvl.lat_ms, 99.0),
            pct(&lvl.lat_ms, 100.0),
        );
    }
}
