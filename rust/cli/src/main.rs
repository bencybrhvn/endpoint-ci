//! Local content-inspection CLI for the PoC — the Rust sibling of `../../cmd/ch-inspect`.
//!
//! ```text
//! ch-inspect --rules config/rules.json --file <path>       scan one file
//! ch-inspect --rules config/rules.json --report            rule compatibility report
//! ch-inspect --rules config/rules.json --bench <dir>       latency percentiles over a flat dir
//! ch-inspect --rules config/rules.json --scan <dir>        real-world profile (recursive)
//! ```

mod bench;
mod report;
mod rss;
mod scan;

use ch_inspect_core::{engine, extract, rules};
use clap::Parser;

#[derive(Parser)]
#[command(about = "Local, offline content-inspection engine (PoC)")]
struct Cli {
    /// Path to rules.json.
    #[arg(long, default_value = "config/rules.json")]
    rules: String,

    /// File to inspect.
    #[arg(long)]
    file: Option<String>,

    /// Print the rule compatibility report and exit.
    #[arg(long)]
    report: bool,

    /// Benchmark: scan every file in a (flat) directory and report latency percentiles.
    #[arg(long)]
    bench: Option<String>,

    /// Profile: recursively inspect real files under a directory.
    #[arg(long)]
    scan: Option<String>,

    /// Size gate: files larger than this are head/tail inspected only.
    #[arg(long = "max-file-mb", default_value_t = 16)]
    max_file_mb: u64,

    /// --scan: skip files larger than this (avoid reading huge files whole).
    #[arg(long = "max-read-mb", default_value_t = 50)]
    max_read_mb: u64,

    /// --scan: show this many slowest files.
    #[arg(long = "top", default_value_t = 10)]
    top: usize,

    /// --scan: cap files processed (0 = all).
    #[arg(long = "max-files", default_value_t = 0)]
    max_files: usize,

    /// --scan: include dot-directories (e.g. .git).
    #[arg(long = "include-hidden", default_value_t = false)]
    include_hidden: bool,

    /// --scan: inspect each file in a child process with an RSS/time watchdog (crash-safe).
    #[arg(long = "isolate", default_value_t = true, action = clap::ArgAction::Set)]
    isolate: bool,

    /// --scan --isolate: kill a child exceeding this RSS.
    #[arg(long = "rss-cap-mb", default_value_t = 512)]
    rss_cap_mb: u64,

    /// --scan --isolate: kill a child running longer than this.
    #[arg(long = "file-timeout-sec", default_value_t = 8)]
    file_timeout_sec: u64,

    /// --scan: write per-file results to this CSV path.
    #[arg(long = "csv")]
    csv: Option<String>,
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
    let cfg = extract::Config {
        max_file_bytes: Some((cli.max_file_mb << 20) as usize),
        ..Default::default()
    };

    if cli.report {
        report::print_report(&db);
        return;
    }
    if let Some(dir) = &cli.bench {
        bench::run_bench(&db, dir, cfg);
        return;
    }
    if let Some(dir) = &cli.scan {
        let self_exe = std::env::current_exe().unwrap_or_else(|e| {
            eprintln!("current_exe: {e}");
            std::process::exit(1);
        });
        let opts = scan::ScanOpts {
            dir: dir.clone(),
            top: cli.top,
            max_files: cli.max_files,
            max_read_bytes: cli.max_read_mb << 20,
            csv_path: cli.csv.clone(),
            include_hidden: cli.include_hidden,
            isolate: cli.isolate,
            rss_cap_mb: cli.rss_cap_mb,
            timeout: std::time::Duration::from_secs(cli.file_timeout_sec),
            self_exe,
            rules_path: cli.rules.clone(),
            max_file_mb: cli.max_file_mb,
        };
        scan::run_scan(&db, cfg, &opts);
        return;
    }
    if let Some(file) = &cli.file {
        match engine::inspect_file(file, &db, cfg) {
            Ok(report) => println!("{}", serde_json::to_string_pretty(&report).expect("Report serialisation cannot fail")),
            Err(e) => {
                eprintln!("inspect file: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    eprintln!("usage: ch-inspect --rules <path> --file <path> | --report | --bench <dir> | --scan <dir>");
    std::process::exit(2);
}
