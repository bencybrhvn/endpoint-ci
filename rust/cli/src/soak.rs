//! `--cpu-soak <dir>`: sustained CPU-utilization measurement against a synthetic "egress event
//! stream", checking the `<=3% CPU` budget line in `../../CLAUDE.md` -- a question `--bench` and
//! `--scan` don't answer. Both of those measure *per-call latency* (how long one inspection
//! takes); the CPU budget is about *sustained utilization over time* against a realistic arrival
//! rate, which a fast engine can still fail if called often enough. No corpus or telemetry gives
//! us a real endpoint's actual event rate, so `--soak-rate` is an explicit, adjustable assumption
//! -- not a measured fact -- and the report says so.
//!
//! Loads the rules DB once and keeps it warm for the whole run, calling `engine::inspect_file`
//! at a fixed rate -- the realistic embedded-sensor shape (a real host loads once, stays
//! resident), unlike `--scan --isolate`'s fresh-process-per-file, which would make CPU%
//! measurement meaningless (dominated by process-spawn cost, not engine cost).

use std::path::PathBuf;
use std::time::{Duration, Instant};

use ch_inspect_core::{engine, extract, rules};
use walkdir::WalkDir;

use crate::rss::{cpu_time, max_rss_bytes};

pub struct SoakOpts {
    pub dir: String,
    pub duration: Duration,
    /// Events per second, arriving at a fixed interval. Real egress traffic is bursty, not
    /// uniform; this is a deliberate simplification, not a claim about real traffic shape.
    pub rate_per_sec: f64,
    pub sample_interval: Duration,
    /// The budget line from ../../CLAUDE.md, purely for the report's pass/fail line -- not
    /// enforced, just checked against.
    pub budget_pct: f64,
}

pub fn run_soak(db: &rules::DB, cfg: extract::Config, o: &SoakOpts) {
    let files: Vec<PathBuf> = WalkDir::new(&o.dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect();
    if files.is_empty() {
        eprintln!("cpu-soak: no files found under {}", o.dir);
        std::process::exit(1);
    }

    if cpu_time().is_none() {
        eprintln!("cpu-soak: getrusage unavailable on this platform");
        std::process::exit(1);
    }

    let interval = Duration::from_secs_f64(1.0 / o.rate_per_sec);
    let poll = interval
        .checked_div(4)
        .unwrap_or(Duration::from_millis(1))
        .clamp(Duration::from_millis(1), Duration::from_millis(20));

    println!("=== endpoint-ci CPU soak (rust) ===");
    println!("corpus:        {} ({} files, cycled)", o.dir, files.len());
    println!(
        "assumed rate:  {:.3} events/sec (1 every {:?}) -- an input assumption, not measured telemetry",
        o.rate_per_sec, interval
    );
    println!("duration:      {:?}", o.duration);
    println!("budget check:  <={:.1}% CPU (../../CLAUDE.md)", o.budget_pct);
    println!();

    let start = Instant::now();
    let mut next_event = start;
    let mut next_sample = start + o.sample_interval;
    let mut last_cpu = cpu_time().unwrap();
    let mut last_sample_at = start;

    let mut file_idx = 0usize;
    let mut events: u64 = 0;
    let mut latencies_us: Vec<u64> = Vec::new();
    let mut window_pcts: Vec<f64> = Vec::new();

    while start.elapsed() < o.duration {
        let now = Instant::now();
        if now >= next_event {
            let path = &files[file_idx % files.len()];
            file_idx += 1;
            let t0 = Instant::now();
            let _ = engine::inspect_file(path.to_str().unwrap_or(""), db, cfg);
            latencies_us.push(t0.elapsed().as_micros() as u64);
            events += 1;
            // Schedule the next arrival off the fixed grid, not off `now`, so a slow event
            // doesn't compound into permanent drift -- but never schedule into the past.
            next_event = (next_event + interval).max(Instant::now());
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
            next_sample += o.sample_interval;
        }
        std::thread::sleep(poll);
    }

    let total_wall = start.elapsed();
    let total_cpu = cpu_time().unwrap_or_default();
    let overall_pct = 100.0 * total_cpu.as_secs_f64() / total_wall.as_secs_f64();

    latencies_us.sort_unstable();
    window_pcts.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pct_at = |v: &[f64], q: f64| -> f64 {
        if v.is_empty() {
            return 0.0;
        }
        v[((v.len() - 1) as f64 * q) as usize]
    };
    let mean_window_pct = if window_pcts.is_empty() {
        0.0
    } else {
        window_pcts.iter().sum::<f64>() / window_pcts.len() as f64
    };

    println!("events processed: {events}");
    println!("wall time:        {total_wall:?}");
    println!();
    println!("per-event engine latency:");
    if !latencies_us.is_empty() {
        let sum: u64 = latencies_us.iter().sum();
        println!(
            "  mean {:.3}ms  p50 {:.3}ms  p95 {:.3}ms  p99 {:.3}ms  max {:.3}ms",
            sum as f64 / latencies_us.len() as f64 / 1000.0,
            latencies_us[latencies_us.len() / 2] as f64 / 1000.0,
            pct_at(&latencies_us.iter().map(|&x| x as f64).collect::<Vec<_>>(), 0.95) / 1000.0,
            pct_at(&latencies_us.iter().map(|&x| x as f64).collect::<Vec<_>>(), 0.99) / 1000.0,
            *latencies_us.last().unwrap() as f64 / 1000.0
        );
    }
    println!();
    println!("CPU utilization (per-{:?} window, {} samples):", o.sample_interval, window_pcts.len());
    println!(
        "  mean {mean_window_pct:.3}%  p50 {:.3}%  p95 {:.3}%  p99 {:.3}%  max {:.3}%",
        pct_at(&window_pcts, 0.50),
        pct_at(&window_pcts, 0.95),
        pct_at(&window_pcts, 0.99),
        window_pcts.last().copied().unwrap_or(0.0)
    );
    println!("  overall (total CPU time / total wall time): {overall_pct:.3}%");
    println!();
    if let Some(rss) = max_rss_bytes() {
        println!("peak RSS: {:.1} MB (budget: <=50 MB)", rss as f64 / (1 << 20) as f64);
    }
    println!();
    let verdict = if mean_window_pct <= o.budget_pct { "WITHIN BUDGET" } else { "OVER BUDGET" };
    println!(
        "budget check: mean {mean_window_pct:.3}% vs <={:.1}% -- {verdict} (assumed rate {:.3} events/sec; rerun with --soak-rate to check other assumptions)",
        o.budget_pct, o.rate_per_sec
    );
}
