//! `ch-inspect-fs-watch --watch-dir <dir>`: Phase 2 of the endpoint-impact lab evaluation (see the
//! `endpoint-ci-lab-evaluation-plan` memory) -- a non-enforcing companion process that watches a
//! directory for file writes and scans each one with `ch-inspect-core`, entirely independent of
//! the real per-platform content scanners (C#/.NET on Windows, Swift on macOS, C/C++ on Linux --
//! see `endpoint-agent-source-locations`). Nothing here touches those; this is a separate process
//! reading files the same way any file-system tool would.
//!
//! Because this runs as its own process rather than being injected into a shared one, its own
//! CPU/RSS footprint over a run *is* the full "additional impact of running the scan on the
//! endpoint" -- there is nothing else on the endpoint for it to have slowed down. That's a
//! narrower, cleaner question than measuring code injected into a real host process would be, and
//! is why this tool reports its own resource usage directly rather than needing a live
//! baseline/treatment toggle across two sessions.
//!
//! Loads the rules DB once and stays warm for the whole run (the realistic embedded-sensor
//! shape), watches `--watch-dir` via the OS's native file-watching API (FSEvents on macOS, the
//! lab endpoint's platform), debounces per-path write events so a file isn't scanned mid-write,
//! and samples CPU%/RSS on a fixed interval -- the same methodology `--cpu-soak`
//! (`../cli/src/soak.rs`) uses against a synthetic loop, applied here to real filesystem events.
//!
//! # Safety
//! Read-only: opens and reads each file's bytes, never writes to or deletes anything in the
//! watched directory. Reports are logged to `--log`, never used to block or modify anything.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ch_inspect_core::{engine, extract, rules};
use clap::Parser;
use notify::{Event, EventKind, RecursiveMode, Watcher};

mod rss;
use rss::{cpu_time, max_rss_bytes};

#[derive(Parser)]
#[command(about = "Non-enforcing filesystem-watch companion for the endpoint-impact lab evaluation")]
struct Cli {
    /// Path to rules.json.
    #[arg(long, default_value = "config/rules.json")]
    rules: String,

    /// Directory to watch for new/modified files.
    #[arg(long = "watch-dir")]
    watch_dir: String,

    /// Recurse into subdirectories.
    #[arg(long, default_value_t = false)]
    recursive: bool,

    /// How long to run before printing a summary and exiting.
    #[arg(long = "duration-sec", default_value_t = 120)]
    duration_sec: u64,

    /// Wait this long after a file's last write event before scanning it, so a file isn't
    /// scanned mid-write.
    #[arg(long = "debounce-ms", default_value_t = 300)]
    debounce_ms: u64,

    /// CPU%/RSS sampling window -- same convention as --cpu-soak.
    #[arg(long = "sample-interval-sec", default_value_t = 1.0)]
    sample_interval_sec: f64,

    /// The <=3% CPU budget line from ../../CLAUDE.md, for the report's pass/fail line only.
    #[arg(long = "budget-pct", default_value_t = 3.0)]
    budget_pct: f64,

    /// JSONL per-file event log (default: ~/.ch-inspect-shadow/fswatch_events.jsonl).
    #[arg(long)]
    log: Option<String>,

    /// Skip dotfiles (default on, matching --scan's default).
    #[arg(long = "include-hidden", default_value_t = false)]
    include_hidden: bool,
}

#[derive(serde::Serialize)]
struct LogLine {
    ts_unix_ms: u128,
    path: String,
    file_bytes: u64,
    /// How long this file sat with no further write events before being scanned -- confirms the
    /// debounce window actually elapsed, not a cost measurement.
    debounce_wait_ms: u64,
    scan_us: u64,
    report: engine::Report,
}

fn log_path(cli_log: &Option<String>) -> PathBuf {
    if let Some(p) = cli_log {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".ch-inspect-shadow").join("fswatch_events.jsonl")
}

fn now_unix_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

fn is_hidden(path: &Path) -> bool {
    path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with('.'))
}

fn scan_one(path: &Path, db: &rules::DB, cfg: extract::Config, log_file: &mut std::fs::File, debounce_wait: Duration) -> Option<u64> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let t0 = Instant::now();
    let report = match engine::inspect_file(path.to_str()?, db, cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("scanning {path:?}: {e}");
            return None;
        }
    };
    let scan_us = t0.elapsed().as_micros() as u64;

    let line = LogLine {
        ts_unix_ms: now_unix_ms(),
        path: path.display().to_string(),
        file_bytes: meta.len(),
        debounce_wait_ms: debounce_wait.as_millis() as u64,
        scan_us,
        report,
    };
    if let Ok(json) = serde_json::to_string(&line) {
        let _ = writeln!(log_file, "{json}");
    }
    Some(scan_us)
}

fn percentile(sorted: &[u64], q: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn main() {
    let cli = Cli::parse();

    let db = match rules::load(&cli.rules) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("load rules: {e}");
            std::process::exit(1);
        }
    };
    let cfg = extract::Config::default();

    if cpu_time().is_none() {
        eprintln!("fs-watch: getrusage unavailable on this platform");
        std::process::exit(1);
    }

    let log_path = log_path(&cli.log);
    if let Some(dir) = log_path.parent()
        && let Err(e) = std::fs::create_dir_all(dir)
    {
        eprintln!("creating log dir {dir:?}: {e}");
        std::process::exit(1);
    }
    let mut log_file = match std::fs::OpenOptions::new().create(true).append(true).open(&log_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("opening log {log_path:?}: {e}");
            std::process::exit(1);
        }
    };

    let (tx, rx) = channel::<notify::Result<Event>>();
    let mut watcher = match notify::recommended_watcher(tx) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("creating watcher: {e}");
            std::process::exit(1);
        }
    };
    let mode = if cli.recursive {
        RecursiveMode::Recursive
    } else {
        RecursiveMode::NonRecursive
    };
    if let Err(e) = watcher.watch(Path::new(&cli.watch_dir), mode) {
        eprintln!("watching {}: {e}", cli.watch_dir);
        std::process::exit(1);
    }

    let duration = Duration::from_secs(cli.duration_sec);
    let debounce = Duration::from_millis(cli.debounce_ms);
    let sample_interval = Duration::from_secs_f64(cli.sample_interval_sec);
    let poll = Duration::from_millis(50);

    println!("=== endpoint-ci fs-watch (rust) ===");
    println!("watching:      {} (recursive: {})", cli.watch_dir, cli.recursive);
    println!("duration:      {duration:?}");
    println!("debounce:      {debounce:?}");
    println!("log:           {log_path:?}");
    println!("budget check:  <={:.1}% CPU (../../CLAUDE.md)", cli.budget_pct);
    println!();

    let start = Instant::now();
    let mut next_sample = start + sample_interval;
    let mut last_cpu = cpu_time().unwrap();
    let mut last_sample_at = start;

    // path -> (last event time, first-seen-pending time)
    let mut pending: HashMap<PathBuf, (Instant, Instant)> = HashMap::new();
    let mut scan_latencies_us: Vec<u64> = Vec::new();
    let mut window_pcts: Vec<f64> = Vec::new();
    let mut files_scanned: u64 = 0;
    let mut events_seen: u64 = 0;

    while start.elapsed() < duration {
        match rx.recv_timeout(poll) {
            Ok(Ok(event)) => {
                events_seen += 1;
                if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                    for path in event.paths {
                        if cli.include_hidden || !is_hidden(&path) {
                            let now = Instant::now();
                            pending.entry(path).and_modify(|(last, _)| *last = now).or_insert((now, now));
                        }
                    }
                }
            }
            Ok(Err(e)) => eprintln!("watch error: {e}"),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }

        let now = Instant::now();

        let ready: Vec<PathBuf> = pending
            .iter()
            .filter(|(_, (last, _))| now.duration_since(*last) >= debounce)
            .map(|(p, _)| p.clone())
            .collect();
        for path in ready {
            if let Some((_, first_seen)) = pending.remove(&path)
                && let Some(us) = scan_one(&path, &db, cfg, &mut log_file, now.duration_since(first_seen))
            {
                scan_latencies_us.push(us);
                files_scanned += 1;
            }
        }

        if now >= next_sample {
            let cpu = cpu_time().unwrap_or(last_cpu);
            let wall = now.duration_since(last_sample_at);
            let cpu_delta = cpu.saturating_sub(last_cpu);
            if wall.as_secs_f64() > 0.0 {
                window_pcts.push(100.0 * cpu_delta.as_secs_f64() / wall.as_secs_f64());
            }
            last_cpu = cpu;
            last_sample_at = now;
            next_sample += sample_interval;
        }
    }

    let total_wall = start.elapsed();
    let total_cpu = cpu_time().unwrap_or_default();
    let overall_pct = if total_wall.as_secs_f64() > 0.0 {
        100.0 * total_cpu.as_secs_f64() / total_wall.as_secs_f64()
    } else {
        0.0
    };

    scan_latencies_us.sort_unstable();
    window_pcts.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean_window_pct = if window_pcts.is_empty() {
        0.0
    } else {
        window_pcts.iter().sum::<f64>() / window_pcts.len() as f64
    };
    let pct_f64 = |v: &[f64], q: f64| -> f64 {
        if v.is_empty() {
            return 0.0;
        }
        v[((v.len() - 1) as f64 * q).round() as usize]
    };

    println!("fs events seen:    {events_seen}");
    println!("files scanned:     {files_scanned}");
    println!("wall time:         {total_wall:?}");
    println!();
    println!("per-file scan latency:");
    if !scan_latencies_us.is_empty() {
        let sum: u64 = scan_latencies_us.iter().sum();
        println!(
            "  mean {:.3}ms  p50 {:.3}ms  p95 {:.3}ms  p99 {:.3}ms  max {:.3}ms",
            sum as f64 / scan_latencies_us.len() as f64 / 1000.0,
            percentile(&scan_latencies_us, 0.50) as f64 / 1000.0,
            percentile(&scan_latencies_us, 0.95) as f64 / 1000.0,
            percentile(&scan_latencies_us, 0.99) as f64 / 1000.0,
            scan_latencies_us.last().copied().unwrap_or(0) as f64 / 1000.0
        );
    } else {
        println!("  (no files scanned -- drop files into the watched directory during the run)");
    }
    println!();
    println!("CPU utilization (per-{sample_interval:?} window, {} samples):", window_pcts.len());
    println!(
        "  mean {mean_window_pct:.3}%  p50 {:.3}%  p95 {:.3}%  p99 {:.3}%  max {:.3}%",
        pct_f64(&window_pcts, 0.50),
        pct_f64(&window_pcts, 0.95),
        pct_f64(&window_pcts, 0.99),
        window_pcts.last().copied().unwrap_or(0.0)
    );
    println!("  overall (total CPU time / total wall time): {overall_pct:.3}%");
    println!();
    if let Some(rss) = max_rss_bytes() {
        println!("peak RSS: {:.1} MB (budget: <=50 MB)", rss as f64 / (1 << 20) as f64);
    }
    println!();
    let verdict = if mean_window_pct <= cli.budget_pct { "WITHIN BUDGET" } else { "OVER BUDGET" };
    println!(
        "budget check: mean {mean_window_pct:.3}% vs <={:.1}% -- {verdict}. This is the tool's OWN footprint as a \
         separate process, not injected into any real scanner -- it is the full additional impact of running it.",
        cli.budget_pct
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_picks_the_nearest_rank() {
        let sorted = vec![10, 20, 30, 40, 50];
        assert_eq!(percentile(&sorted, 0.0), 10);
        assert_eq!(percentile(&sorted, 1.0), 50);
        assert_eq!(percentile(&sorted, 0.5), 30);
    }

    #[test]
    fn percentile_of_empty_is_zero_not_a_panic() {
        assert_eq!(percentile(&[], 0.5), 0);
    }

    #[test]
    fn is_hidden_detects_leading_dot_files_only() {
        assert!(is_hidden(Path::new("/tmp/.hidden")));
        assert!(!is_hidden(Path::new("/tmp/visible.txt")));
    }

    #[test]
    fn scan_one_logs_a_jsonl_line_and_returns_the_scan_latency() {
        let dir = std::env::temp_dir().join(format!("ch-fswatch-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("sample.txt");
        std::fs::write(&file_path, "no sensitive data here, just prose").unwrap();
        let log_path = dir.join("log.jsonl");

        let rules_path = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/rules.json"));
        let db = rules::load(rules_path.to_str().unwrap()).expect("load real rules.json");
        let cfg = extract::Config::default();
        let mut log_file = std::fs::OpenOptions::new().create(true).append(true).open(&log_path).unwrap();

        let result = scan_one(&file_path, &db, cfg, &mut log_file, Duration::from_millis(300));
        assert!(result.is_some());

        let logged = std::fs::read_to_string(&log_path).unwrap();
        assert!(logged.contains("sample.txt"));
        assert!(logged.contains("debounce_wait_ms"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scan_one_on_a_directory_is_none_not_a_panic() {
        let dir = std::env::temp_dir().join(format!("ch-fswatch-dirtest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let rules_path = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/rules.json"));
        let db = rules::load(rules_path.to_str().unwrap()).expect("load real rules.json");
        let cfg = extract::Config::default();
        let log_path = dir.join("log.jsonl");
        let mut log_file = std::fs::OpenOptions::new().create(true).append(true).open(&log_path).unwrap();

        assert!(scan_one(&dir, &db, cfg, &mut log_file, Duration::from_millis(0)).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }
}
