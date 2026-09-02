//! `--scan <dir>`: recursively inspects real files and reports a real-world profile (latency
//! percentiles, throughput, verdict/file-type breakdowns, slowest files, peak RSS). The Rust
//! sibling of Go's `runScan`/`inspectIsolated`.
//!
//! `--isolate` (default on) runs each file through a *child process* (`self --file <path>`)
//! with an RSS-cap + timeout watchdog, so a memory-bomb or hanging file (the real PDF DoS Go's
//! port found — see `../../DECISIONS.md`, "Real-world profiler + PDF DoS isolation") only ever
//! kills the child, not this scan. Per-file latency in the report comes from the *child's*
//! self-reported `scan_duration_us` (accurate, in-child), not the round-trip including process
//! spawn + rules reload — matching Go's own reporting split between "wall time" (everything)
//! and "per-file latency" (pure engine cost).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ch_inspect_core::{engine, extract, rules};
use walkdir::WalkDir;

use crate::rss::max_rss_bytes;

pub struct ScanOpts {
    pub dir: String,
    pub top: usize,
    pub max_files: usize,
    pub max_read_bytes: u64,
    pub csv_path: Option<String>,
    pub include_hidden: bool,
    pub isolate: bool,
    pub rss_cap_mb: u64,
    pub timeout: Duration,
    pub self_exe: PathBuf,
    pub rules_path: String,
    pub max_file_mb: u64,
}

struct FileResult {
    path: String,
    size: u64,
    ftype: String,
    /// >=1 profile matched.
    matched: bool,
    /// >=1 profile at/above the high-confidence threshold.
    high_conf: bool,
    /// Body was content-inspected.
    readable: bool,
    micros: i64,
    partial: bool,
    short: bool,
}

pub fn run_scan(db: &rules::DB, cfg: extract::Config, o: &ScanOpts) {
    let mut results: Vec<FileResult> = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut skipped_large = 0u64;
    let mut killed = 0u64;
    let verbose = std::env::var("CH_VERBOSE").is_ok();

    let wall_start = Instant::now();

    let walker = WalkDir::new(&o.dir).into_iter().filter_entry(|e| {
        if e.depth() == 0 || !e.file_type().is_dir() {
            return true;
        }
        // Skip dot-directories (.git, .cache, …) unless asked to include them.
        let name = e.file_name().to_string_lossy();
        o.include_hidden || !(name.len() > 1 && name.starts_with('.'))
    });

    'walk: for entry in walker.filter_map(Result::ok) {
        if !entry.file_type().is_file() {
            continue;
        }
        if o.max_files > 0 && results.len() >= o.max_files {
            break 'walk;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if o.max_read_bytes > 0 && meta.len() > o.max_read_bytes {
            skipped_large += 1;
            continue;
        }
        let path_str = entry.path().to_string_lossy().into_owned();
        if verbose {
            eprintln!("{path_str}");
        }

        let report = if o.isolate {
            inspect_isolated(o, &path_str)
        } else {
            engine::inspect_file(&path_str, db, cfg).ok()
        };
        total_bytes += meta.len();
        match report {
            None => {
                // Child killed (OOM/timeout) or unreadable — record so it's visible.
                killed += 1;
                results.push(FileResult {
                    path: path_str,
                    size: meta.len(),
                    ftype: "(killed)".to_string(),
                    matched: false,
                    high_conf: false,
                    readable: false,
                    micros: o.timeout.as_micros() as i64,
                    partial: false,
                    short: false,
                });
            }
            Some(v) => results.push(FileResult {
                path: path_str,
                size: meta.len(),
                ftype: v.file_type.clone(),
                matched: v.matched(),
                high_conf: v.high_confidence(db.conf.high_confidence_threshold),
                readable: v.readable,
                micros: v.scan_micros,
                partial: v.coverage != engine::COVERAGE_FULL,
                short: v.short_circuited,
            }),
        }
    }
    let wall = wall_start.elapsed();

    if results.is_empty() {
        println!("no files inspected");
        return;
    }

    let mut types: HashMap<String, usize> = HashMap::new();
    let (mut partial, mut short, mut matched, mut high_conf, mut unreadable) = (0usize, 0usize, 0usize, 0usize, 0usize);
    let mut sum_micros: i64 = 0;
    for r in &results {
        *types.entry(r.ftype.clone()).or_insert(0) += 1;
        matched += r.matched as usize;
        high_conf += r.high_conf as usize;
        unreadable += !r.readable as usize;
        partial += r.partial as usize;
        short += r.short as usize;
        sum_micros += r.micros;
    }
    let mut micros_sorted: Vec<i64> = results.iter().map(|r| r.micros).collect();
    micros_sorted.sort_unstable();
    let pct = |q: f64| Duration::from_micros(micros_sorted[((micros_sorted.len() - 1) as f64 * q) as usize].max(0) as u64);

    let n = results.len();
    let mb_total = total_bytes as f64 / (1 << 20) as f64;
    let scan_secs = sum_micros as f64 / 1e6;

    println!("=== endpoint-ci real-world scan (rust) ===");
    println!("root:            {}", o.dir);
    println!(
        "files inspected: {n}   (skipped >{}MB: {skipped_large}, killed OOM/timeout: {killed})",
        o.max_read_bytes / (1 << 20)
    );
    if o.isolate {
        println!("isolation:       on (child per file, RSS cap {}MB, timeout {:?})", o.rss_cap_mb, o.timeout);
    }
    println!("total content:   {mb_total:.1} MB");
    println!("wall time:       {:?}   (inspect-only CPU: {scan_secs:.2}s)", wall);
    if scan_secs > 0.0 {
        println!(
            "throughput:      {:.1} MB/s, {:.0} files/s (inspect-only)",
            mb_total / scan_secs,
            n as f64 / scan_secs
        );
    }

    println!("\nper-file latency:");
    println!(
        "  mean {:?}  p50 {:?}  p90 {:?}  p95 {:?}  p99 {:?}  max {:?}",
        Duration::from_micros((sum_micros / n as i64).max(0) as u64),
        pct(0.50),
        pct(0.90),
        pct(0.95),
        pct(0.99),
        Duration::from_micros(*micros_sorted.last().unwrap() as u64)
    );

    let pct_of = |x: usize| 100.0 * x as f64 / n as f64;
    println!(
        "\nmatches:   clean={} ({:.0}%)  matched={matched} ({:.0}%)  of-which-high-confidence={high_conf}  unreadable={unreadable}",
        n - matched,
        pct_of(n - matched),
        pct_of(matched)
    );
    println!("short-circuited: {short}   partial (size gate): {partial}");

    println!("\nfile types:");
    let mut type_counts: Vec<(&String, &usize)> = types.iter().collect();
    type_counts.sort_by(|a, b| b.1.cmp(a.1));
    for (k, v) in type_counts {
        println!("  {k:<12} {v}");
    }

    println!("\nslowest {} files:", o.top.min(n));
    let mut slow: Vec<&FileResult> = results.iter().collect();
    slow.sort_by_key(|r| std::cmp::Reverse(r.micros));
    let label = |r: &FileResult| -> &'static str {
        if !r.readable {
            "unreadable"
        } else if r.high_conf {
            "match:high"
        } else if r.matched {
            "match"
        } else {
            "clean"
        }
    };
    for r in slow.iter().take(o.top) {
        println!(
            "  {:7.2} ms  {:<10} {:<9} {:8.0} KB  {}",
            r.micros as f64 / 1000.0,
            label(r),
            r.ftype,
            r.size as f64 / 1024.0,
            r.path
        );
    }

    if let Some(rss) = max_rss_bytes() {
        println!("\nmemory impact:\n  peak RSS: {:.1} MB (budget: <=50 MB)", rss as f64 / (1 << 20) as f64);
    }

    if let Some(csv_path) = &o.csv_path {
        match write_csv(csv_path, &results) {
            Ok(()) => println!("\nper-file CSV written: {csv_path}"),
            Err(e) => eprintln!("csv: {e}"),
        }
    }
}

/// Runs `self --file <path>` as a child process with an RSS watchdog + timeout, so a
/// memory-bomb file (e.g. a malicious PDF) only kills the child. Returns `None` on any
/// failure to spawn/parse or if the watchdog had to kill it.
fn inspect_isolated(o: &ScanOpts, path: &str) -> Option<engine::Report> {
    let mut child = std::process::Command::new(&o.self_exe)
        .arg("--rules")
        .arg(&o.rules_path)
        .arg("--file")
        .arg(path)
        .arg("--max-file-mb")
        .arg(o.max_file_mb.to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;

    let pid = child.id();
    let stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        use std::io::Read;
        let mut stdout = stdout;
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });

    // Signalled (not polled via the pid, which the OS can recycle after exit) so the watchdog
    // never risks killing an unrelated process that reused this pid after our child exited.
    let done = Arc::new(AtomicBool::new(false));
    let done_for_watchdog = done.clone();
    let deadline = Instant::now() + o.timeout;
    let cap_bytes = o.rss_cap_mb * (1 << 20);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_millis(150));
            if done_for_watchdog.load(Ordering::Relaxed) {
                return;
            }
            if Instant::now() >= deadline || rss_bytes(pid) > cap_bytes {
                unsafe {
                    libc::kill(pid as libc::pid_t, libc::SIGKILL);
                }
                return;
            }
        }
    }); // deliberately not joined: it exits within 150ms of `done` being set, harmless to leak

    let status = child.wait().ok()?;
    done.store(true, Ordering::Relaxed);
    let out = reader.join().ok()?;

    if !status.success() {
        return None;
    }
    serde_json::from_slice(&out).ok()
}

/// A process's resident set size via `ps` (darwin/linux) — the same approach Go's `rssBytes`
/// uses; there's no portable way to read a *different* live process's RSS without it.
fn rss_bytes(pid: u32) -> u64 {
    let Ok(out) = std::process::Command::new("ps").arg("-o").arg("rss=").arg("-p").arg(pid.to_string()).output() else {
        return 0;
    };
    String::from_utf8_lossy(&out.stdout).trim().parse::<u64>().map(|kb| kb * 1024).unwrap_or(0)
}

fn write_csv(path: &str, results: &[FileResult]) -> std::io::Result<()> {
    let mut w = csv::Writer::from_path(path)?;
    w.write_record([
        "path",
        "bytes",
        "type",
        "matched",
        "high_confidence",
        "readable",
        "micros",
        "partial",
        "short_circuit",
    ])?;
    for r in results {
        w.write_record([
            r.path.as_str(),
            &r.size.to_string(),
            &r.ftype,
            &r.matched.to_string(),
            &r.high_conf.to_string(),
            &r.readable.to_string(),
            &r.micros.to_string(),
            &r.partial.to_string(),
            &r.short.to_string(),
        ])?;
    }
    w.flush()?;
    Ok(())
}
