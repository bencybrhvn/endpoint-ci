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
//! # Larger on-prem files: isolation above a configurable size, not a bigger gate alone
//! `--max-file-mb` (the extraction-layer size gate) only bounds *plaintext* files and the text
//! *returned* from OOXML/PDF -- `pdf-extract` always fully parses a PDF's content regardless of
//! that gate (confirmed in `core/src/extract.rs`), so raising it does nothing for the known
//! large-PDF residual RSS issue (`../vendor/pdf-extract/PATCH.md`'s "Residual ~9%..." section).
//! The actual safety net for a large or pathological file is the same one `--scan --isolate`
//! (`../cli/src/scan.rs`) already uses: run it in a child process with an RSS-cap + timeout
//! watchdog, so only the child dies. Files at or above `--isolate-above-mb` go through that path;
//! smaller files stay in the fast, warm, in-process path this tool was originally measured with
//! (Phase 1/2's validated low-overhead numbers still hold for that common case).
//!
//! # Safety
//! Read-only: opens and reads each file's bytes, never writes to or deletes anything in the
//! watched directory. Reports are logged to `--log`, never used to block or modify anything.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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

    /// Single-file mode: inspect one file, print its report as JSON, and exit -- used internally
    /// when this binary re-execs itself as an isolated child (see --isolate-above-mb), but usable
    /// standalone too.
    #[arg(long)]
    file: Option<String>,

    /// Directory to watch for new/modified files.
    #[arg(long = "watch-dir")]
    watch_dir: Option<String>,

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

    /// Size gate passed through to the extraction layer: above this, plaintext files are
    /// head/tail-truncated (does NOT bound PDF/OOXML parsing cost -- see the module doc).
    #[arg(long = "max-file-mb", default_value_t = 16)]
    max_file_mb: u64,

    /// Files at or above this size are scanned in an isolated child process with an RSS/timeout
    /// watchdog instead of in-process, so a large or pathological file can only take down its own
    /// child. Set to 0 to always isolate, or a very large value to effectively disable isolation.
    #[arg(long = "isolate-above-mb", default_value_t = 16)]
    isolate_above_mb: u64,

    /// Isolated child RSS cap -- same convention as --scan --isolate.
    #[arg(long = "rss-cap-mb", default_value_t = 512)]
    rss_cap_mb: u64,

    /// Isolated child timeout -- same convention as --scan --isolate.
    #[arg(long = "file-timeout-sec", default_value_t = 8)]
    file_timeout_sec: u64,
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
    /// Scanned via the isolated-child path (file_bytes >= --isolate-above-mb) rather than
    /// in-process.
    isolated: bool,
    /// The isolated child was killed by the RSS/timeout watchdog -- `report` is `None` when true.
    killed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    report: Option<engine::Report>,
}

enum ScanOutcome {
    Completed { report: Box<engine::Report>, latency_us: u64 },
    Killed { latency_us: u64 },
    Failed,
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

fn scan_in_process(path: &str, db: &rules::DB, cfg: extract::Config) -> ScanOutcome {
    let t0 = Instant::now();
    match engine::inspect_file(path, db, cfg) {
        Ok(report) => ScanOutcome::Completed {
            report: Box::new(report),
            latency_us: t0.elapsed().as_micros() as u64,
        },
        Err(e) => {
            eprintln!("scanning {path}: {e}");
            ScanOutcome::Failed
        }
    }
}

/// Mirrors `cli/src/scan.rs`'s `inspect_isolated`: runs `self_exe --file <path>` as a child with
/// an RSS-cap + timeout watchdog, so a memory-bomb or hanging file only kills the child.
fn scan_isolated(self_exe: &Path, rules_path: &str, max_file_mb: u64, path: &str, rss_cap_mb: u64, timeout: Duration) -> ScanOutcome {
    let t0 = Instant::now();
    let Ok(mut child) = std::process::Command::new(self_exe)
        .arg("--rules")
        .arg(rules_path)
        .arg("--file")
        .arg(path)
        .arg("--max-file-mb")
        .arg(max_file_mb.to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        eprintln!("spawning isolated scan for {path}");
        return ScanOutcome::Failed;
    };

    let pid = child.id();
    let Some(stdout) = child.stdout.take() else {
        return ScanOutcome::Failed;
    };
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
    let deadline = Instant::now() + timeout;
    let cap_bytes = rss_cap_mb.saturating_mul(1 << 20);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_millis(150));
            if done_for_watchdog.load(Ordering::Relaxed) {
                return;
            }
            if Instant::now() >= deadline || child_rss_bytes(pid) > cap_bytes {
                unsafe {
                    libc::kill(pid as libc::pid_t, libc::SIGKILL);
                }
                return;
            }
        }
    }); // deliberately not joined: it exits within 150ms of `done` being set, harmless to leak

    let Ok(status) = child.wait() else {
        return ScanOutcome::Failed;
    };
    done.store(true, Ordering::Relaxed);
    let latency_us = t0.elapsed().as_micros() as u64;
    let Ok(out) = reader.join() else {
        return ScanOutcome::Failed;
    };

    if !status.success() {
        return ScanOutcome::Killed { latency_us };
    }
    match serde_json::from_slice(&out) {
        Ok(report) => ScanOutcome::Completed {
            report: Box::new(report),
            latency_us,
        },
        Err(_) => ScanOutcome::Killed { latency_us },
    }
}

/// A process's resident set size via `ps` -- same approach as `cli/src/rss.rs`'s
/// `cli/src/scan.rs::rss_bytes`; there's no portable way to read a *different* live process's
/// RSS without shelling out.
fn child_rss_bytes(pid: u32) -> u64 {
    let Ok(out) = std::process::Command::new("ps").arg("-o").arg("rss=").arg("-p").arg(pid.to_string()).output() else {
        return 0;
    };
    String::from_utf8_lossy(&out.stdout).trim().parse::<u64>().map(|kb| kb * 1024).unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
fn scan_one(
    path: &Path,
    db: &rules::DB,
    cfg: extract::Config,
    log_file: &mut std::fs::File,
    debounce_wait: Duration,
    self_exe: Option<&Path>,
    rules_path: &str,
    max_file_mb: u64,
    isolate_above_mb: u64,
    rss_cap_mb: u64,
    file_timeout: Duration,
) -> ScanOutcome {
    let Ok(meta) = std::fs::metadata(path) else {
        return ScanOutcome::Failed;
    };
    if !meta.is_file() {
        return ScanOutcome::Failed;
    }
    let Some(path_str) = path.to_str() else {
        return ScanOutcome::Failed;
    };

    let large = should_isolate(meta.len(), isolate_above_mb);
    let outcome = match (large, self_exe) {
        (true, Some(exe)) => scan_isolated(exe, rules_path, max_file_mb, path_str, rss_cap_mb, file_timeout),
        _ => scan_in_process(path_str, db, cfg),
    };
    let isolated = large && self_exe.is_some();

    let line = match &outcome {
        ScanOutcome::Completed { report, latency_us } => LogLine {
            ts_unix_ms: now_unix_ms(),
            path: path.display().to_string(),
            file_bytes: meta.len(),
            debounce_wait_ms: debounce_wait.as_millis() as u64,
            scan_us: *latency_us,
            isolated,
            killed: false,
            report: Some(report.as_ref().clone()),
        },
        ScanOutcome::Killed { latency_us } => LogLine {
            ts_unix_ms: now_unix_ms(),
            path: path.display().to_string(),
            file_bytes: meta.len(),
            debounce_wait_ms: debounce_wait.as_millis() as u64,
            scan_us: *latency_us,
            isolated,
            killed: true,
            report: None,
        },
        ScanOutcome::Failed => return outcome,
    };
    if let Ok(json) = serde_json::to_string(&line) {
        let _ = writeln!(log_file, "{json}");
    }
    outcome
}

/// `isolate_above_mb` of `0` means "always isolate"; a very large value (e.g. `u64::MAX`, used to
/// mean "never isolate") must not overflow computing the byte threshold -- `saturating_mul`
/// pins it to `u64::MAX`, which no real file size will ever reach.
fn should_isolate(file_bytes: u64, isolate_above_mb: u64) -> bool {
    file_bytes >= isolate_above_mb.saturating_mul(1 << 20)
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

    // Single-file mode: mirrors ch-inspect's own --file, and is how this binary re-execs itself
    // as an isolated child (see scan_isolated). Handled before anything else needs to exist.
    if let Some(file) = &cli.file {
        let db = match rules::load(&cli.rules) {
            Ok(db) => db,
            Err(e) => {
                eprintln!("load rules: {e}");
                std::process::exit(1);
            }
        };
        let cfg = extract::Config {
            max_file_bytes: Some((cli.max_file_mb << 20) as usize),
            ..Default::default()
        };
        match engine::inspect_file(file, &db, cfg) {
            Ok(report) => println!("{}", serde_json::to_string(&report).expect("Report serialisation cannot fail")),
            Err(e) => {
                eprintln!("inspect file: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    let Some(watch_dir) = &cli.watch_dir else {
        eprintln!("usage: ch-inspect-fs-watch --rules <path> --watch-dir <dir> | --file <path>");
        std::process::exit(2);
    };

    let db = match rules::load(&cli.rules) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("load rules: {e}");
            std::process::exit(1);
        }
    };
    let cfg = extract::Config {
        max_file_bytes: Some((cli.max_file_mb << 20) as usize),
        ..Default::default()
    };

    if cpu_time().is_none() {
        eprintln!("fs-watch: getrusage unavailable on this platform");
        std::process::exit(1);
    }

    let self_exe = std::env::current_exe().ok();
    if self_exe.is_none() {
        eprintln!("warning: current_exe() unavailable -- isolation disabled, all files will scan in-process");
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
    if let Err(e) = watcher.watch(Path::new(watch_dir), mode) {
        eprintln!("watching {watch_dir}: {e}");
        std::process::exit(1);
    }

    let duration = Duration::from_secs(cli.duration_sec);
    let debounce = Duration::from_millis(cli.debounce_ms);
    let sample_interval = Duration::from_secs_f64(cli.sample_interval_sec);
    let file_timeout = Duration::from_secs(cli.file_timeout_sec);
    let poll = Duration::from_millis(50);

    println!("=== endpoint-ci fs-watch (rust) ===");
    println!("watching:      {watch_dir} (recursive: {})", cli.recursive);
    println!("duration:      {duration:?}");
    println!("debounce:      {debounce:?}");
    println!("log:           {log_path:?}");
    println!(
        "size gate:     --max-file-mb {} (bounds plaintext/extracted-text, not PDF parse cost)",
        cli.max_file_mb
    );
    if self_exe.is_some() {
        println!(
            "isolation:     files >= {}MB run isolated (RSS cap {}MB, timeout {:?})",
            cli.isolate_above_mb, cli.rss_cap_mb, file_timeout
        );
    } else {
        println!("isolation:     disabled (current_exe unavailable)");
    }
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
    let mut files_killed: u64 = 0;
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
            let Some((_, first_seen)) = pending.remove(&path) else { continue };
            let outcome = scan_one(
                &path,
                &db,
                cfg,
                &mut log_file,
                now.duration_since(first_seen),
                self_exe.as_deref(),
                &cli.rules,
                cli.max_file_mb,
                cli.isolate_above_mb,
                cli.rss_cap_mb,
                file_timeout,
            );
            match outcome {
                ScanOutcome::Completed { latency_us, .. } => {
                    scan_latencies_us.push(latency_us);
                    files_scanned += 1;
                }
                ScanOutcome::Killed { .. } => files_killed += 1,
                ScanOutcome::Failed => {}
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
    println!("files scanned:     {files_scanned}   killed (RSS/timeout): {files_killed}");
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

    fn real_rules_path() -> PathBuf {
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/rules.json"))
    }

    #[test]
    fn scan_one_logs_a_jsonl_line_in_process_for_a_small_file() {
        let dir = std::env::temp_dir().join(format!("ch-fswatch-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("sample.txt");
        std::fs::write(&file_path, "no sensitive data here, just prose").unwrap();
        let log_path = dir.join("log.jsonl");

        let db = rules::load(real_rules_path().to_str().unwrap()).expect("load real rules.json");
        let cfg = extract::Config::default();
        let mut log_file = std::fs::OpenOptions::new().create(true).append(true).open(&log_path).unwrap();

        // isolate_above_mb huge -> always in-process, matching the common (small-file) case.
        let outcome = scan_one(
            &file_path,
            &db,
            cfg,
            &mut log_file,
            Duration::from_millis(300),
            None,
            "",
            16,
            u64::MAX,
            512,
            Duration::from_secs(8),
        );
        assert!(matches!(outcome, ScanOutcome::Completed { .. }));

        let logged = std::fs::read_to_string(&log_path).unwrap();
        assert!(logged.contains("sample.txt"));
        assert!(logged.contains("\"isolated\":false"));
        assert!(logged.contains("\"killed\":false"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scan_one_on_a_directory_fails_cleanly_not_a_panic() {
        let dir = std::env::temp_dir().join(format!("ch-fswatch-dirtest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = rules::load(real_rules_path().to_str().unwrap()).expect("load real rules.json");
        let cfg = extract::Config::default();
        let log_path = dir.join("log.jsonl");
        let mut log_file = std::fs::OpenOptions::new().create(true).append(true).open(&log_path).unwrap();

        let outcome = scan_one(
            &dir,
            &db,
            cfg,
            &mut log_file,
            Duration::from_millis(0),
            None,
            "",
            16,
            u64::MAX,
            512,
            Duration::from_secs(8),
        );
        assert!(matches!(outcome, ScanOutcome::Failed));
        std::fs::remove_dir_all(&dir).ok();
    }

    // `scan_isolated`'s actual child-process/watchdog mechanics (spawn, RSS/timeout kill, parse
    // stdout) aren't unit-tested here, deliberately -- under `cargo test`, `std::env::current_exe()`
    // resolves to the auto-generated test-harness binary, not a binary that understands our
    // --rules/--file contract, and `CARGO_BIN_EXE_<name>` is only available to integration tests
    // (this crate has no lib.rs for one to depend on). This mirrors `cli/src/scan.rs`'s own
    // `inspect_isolated`, which has no unit tests for the same reason -- validated instead via a
    // real CLI run (see docs/endpoint-impact-evaluation.md). `should_isolate`'s pure threshold
    // logic, including the overflow fix, IS unit-tested below.

    #[test]
    fn should_isolate_at_or_above_the_threshold_only() {
        assert!(!should_isolate(15 << 20, 16)); // 15MB file, 16MB threshold -> in-process
        assert!(should_isolate(16 << 20, 16)); // exactly at the threshold -> isolated
        assert!(should_isolate(17 << 20, 16));
    }

    #[test]
    fn should_isolate_zero_means_always() {
        assert!(should_isolate(0, 0));
        assert!(should_isolate(1, 0));
    }

    #[test]
    fn should_isolate_max_threshold_means_never_for_any_realistic_file_and_does_not_overflow() {
        // Regression test: isolate_above_mb.saturating_mul(1<<20) previously overflowed with a
        // plain `*`, panicking ("attempt to multiply with overflow") for any file at all.
        assert!(!should_isolate(500 << 20, u64::MAX)); // 500MB file, "never isolate" threshold
        assert!(!should_isolate(0, u64::MAX));
    }
}
