//! `--bench <dir>`: latency percentiles over a flat directory, plus a synthetic dense-PII
//! check and peak RSS — checks the resource budget in `../../CLAUDE.md` against this port
//! directly (not just against Go's). The Rust sibling of Go's `runBench`.

use std::time::{Duration, Instant};

use ch_inspect_core::{engine, extract, rules};

use crate::rss::max_rss_bytes;

/// Benchmarks over a flat directory (skips subdirs and `.json` sidecar files, matching Go's
/// `runBench`), plus a synthetic dense-PII check at 200B/8KB/500KB/5MB (the 8KB/500KB tiers
/// mirror Go's `BenchmarkInspect8K`/`BenchmarkInspect500K`; 200B and 5MB round out both ends of
/// the budget tiers) and peak RSS — the two hard numeric lines in that budget (<100ms/≤500KB,
/// <500ms/500KB-5MB, ≤50MB peak RAM). The ≤3% CPU budget needs `--scan` measured against a
/// real egress-like corpus over time, so it isn't checked here. Note the directory benchmark
/// includes per-file disk I/O (open/read/close) on top of the engine's own work — that's real
/// and expected, not an engine inefficiency; the in-process synthetic 200B figure isolates
/// pure engine overhead for comparison.
pub fn run_bench(db: &rules::DB, dir: &str, cfg: extract::Config) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("bench dir: {e}");
            std::process::exit(1);
        }
    };

    let mut durs = Vec::new();
    let mut total_bytes: u64 = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() || path.extension().is_some_and(|e| e == "json") {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        total_bytes += meta.len();
        let start = Instant::now();
        let _ = engine::inspect_file(path.to_str().unwrap(), db, cfg);
        durs.push(start.elapsed());
    }
    if durs.is_empty() {
        println!("no files to benchmark");
        return;
    }
    durs.sort();

    println!("Benchmark over {} files ({total_bytes} bytes total)", durs.len());
    let sum: Duration = durs.iter().sum();
    println!("  mean: {:?}", sum / durs.len() as u32);
    println!("  p50:  {:?}", percentile(&durs, 0.50));
    println!("  p95:  {:?}", percentile(&durs, 0.95));
    println!("  p99:  {:?}", percentile(&durs, 0.99));
    println!("  max:  {:?}", durs[durs.len() - 1]);

    println!("\nSynthetic dense-PII (budget: <100ms for <=500KB, <500ms for 500KB-5MB):");
    for (label, n, iters) in [
        ("200B", 200usize, 2000),
        ("8KB", 8usize << 10, 200),
        ("500KB", 500usize << 10, 20),
        ("5MB", 5usize << 20, 5),
    ] {
        let text = make_large(n);
        let start = Instant::now();
        for _ in 0..iters {
            engine::inspect(label, &text, db);
        }
        let per_iter = start.elapsed() / iters;
        let mb_per_sec = (text.len() as f64 / per_iter.as_secs_f64()) / (1 << 20) as f64;
        println!("  {label:<6} {per_iter:?}/inspect  ({mb_per_sec:.1} MB/s)");
    }

    if let Some(rss) = max_rss_bytes() {
        println!("\npeak RSS: {:.1} MB (budget: <=50 MB)", rss as f64 / (1 << 20) as f64);
    }
}

fn percentile(sorted: &[Duration], q: f64) -> Duration {
    sorted[((sorted.len() - 1) as f64 * q) as usize]
}

/// Builds a buffer of at least `n` bytes densely packed with PII (one of every major detector
/// kind), for a worst-case latency check. Mirrors `makeLarge` in
/// `../../internal/engine/engine_test.go`.
pub fn make_large(n: usize) -> String {
    let block = "Lorem ipsum dolor sit amet. Contact john.doe@example.com or (415) 555-2671. \
                 Card 4111111111111111. SSN 123-45-6789. NPI 1234567893. IBAN GB82WEST12345698765432.\n";
    let mut s = String::new();
    while s.len() < n {
        s.push_str(block);
    }
    s
}
