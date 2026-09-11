//! Non-enforcing Claude Code hook for the lab evaluation of `ch_local_inspect` against the real
//! Cyberhaven client's AI-prompt-security path (`dataflow/Sensors/AI/cyberhaven-agent-inspector`,
//! which today only captures content for async cloud classification -- no synchronous decision).
//!
//! This binary mirrors that capture shape locally: on `UserPromptSubmit`/`PreToolUse` it extracts
//! the same kind of content, inspects it with `ch-inspect-core` directly (no FFI -- this process
//! *is* the integration point, same as any hook written in any other language), and appends one
//! JSONL line per event to a log for later comparison against the same content's eventual cloud
//! incident (detection parity) and against the ~2s latency ceiling a real blocking hook would need
//! (`rules_load_us`/`engine_scan_us`/`engine_call_us`/`harness_total_us` below).
//!
//! Run with `--analyze [path]` (default: the same log this binary writes to) to aggregate that
//! log into per-event latency percentiles -- Phase 1 of the endpoint-impact evaluation
//! ([[endpoint-ci-lab-evaluation-plan]]): does running local inspection add meaningful latency to
//! the hook path? Real Claude Code hook invocations never pass args, so `--analyze` can only be
//! reached by a deliberate manual invocation, never by Claude Code itself.
//!
//! # Safety contract: this must never affect the real Claude Code session
//! - Always exits 0 (see `main`), regardless of what happens inside `run`.
//! - Never writes anything to stdout (only Claude Code-visible channel for a hook's decision).
//! - No `.unwrap()`/`.expect()` on anything derived from the hook payload -- malformed or
//!   unexpected input degrades to a logged error, never a panic.
//!
//! # Wiring
//! Register ALONGSIDE any existing hooks in `.claude/settings.json` -- do not replace them
//! (Claude Code runs every matching hook for an event):
//! ```json
//! {
//!   "hooks": {
//!     "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "/path/to/ch-inspect-claude-hook"}]}],
//!     "PreToolUse":       [{"hooks": [{"type": "command", "command": "/path/to/ch-inspect-claude-hook"}]}]
//!   }
//! }
//! ```
//!
//! # Configuration (both optional)
//! - `CH_SHADOW_RULES`: path to `rules.json` (default: `rules.json` next to this binary, so a
//!   deploy bundle of {binary, rules.json, lexicons/} is self-contained).
//! - `CH_SHADOW_LOG`: path to the JSONL output (default: `~/.ch-inspect-shadow/events.jsonl`).

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ch_inspect_core::{engine, rules};

/// Real Claude Code hook invocations never pass args (see the module doc's wiring example --
/// the command is registered with no arguments), so `--analyze` can only be reached by a
/// deliberate manual CLI invocation, never by Claude Code itself.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(pos) = args.iter().position(|a| a == "--analyze") {
        let path = args.get(pos + 1).map(PathBuf::from).unwrap_or_else(log_path);
        match analyze_log(&path) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("analyze failed: {e}");
                std::process::exit(1);
            }
        }
    }

    let _ = run();
    // Unconditional, regardless of `run`'s outcome: nothing this process does may look like a
    // hook failure/block to Claude Code. See the module doc's safety contract.
    std::process::exit(0);
}

#[derive(serde::Serialize)]
struct LogLine {
    ts_unix_ms: u128,
    session_id: String,
    event: String,
    content_bytes: usize,
    /// Cost of `rules::load` on this call. A real embedding would load once and stay warm (see
    /// module doc); this is reported separately from `engine_scan_us` so a fresh-process-per-hook
    /// deployment's overhead doesn't get mistaken for the engine's own marginal cost.
    rules_load_us: u64,
    /// The engine's own report of its scan time (`Report::scan_micros`) -- the number that's
    /// directly comparable to the benchmarks in `../deliverables/benchmark_results.txt`.
    engine_scan_us: i64,
    /// Harness-measured wall clock for the `engine::inspect` call itself. Usually close to
    /// `engine_scan_us` (the engine's own self-reported timer) but measured independently so a
    /// gap between the two is visible rather than assumed away. `rules_load_us + engine_call_us`
    /// is the actual added latency a real (warm, load-once) embedding would attribute to running
    /// local inspection -- `harness_total_us` also includes stdin read time this dev harness pays
    /// per-invocation that a real embedding wouldn't.
    engine_call_us: u64,
    /// Wall clock from the first line of `run` to the log write, i.e. this hook's full marginal
    /// latency as Claude Code would experience it (stdin read + rules load + scan).
    harness_total_us: u64,
    report: engine::Report,
}

fn run() -> Result<(), String> {
    let t0 = Instant::now();

    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw).map_err(|e| format!("reading stdin: {e}"))?;
    let payload = parse_payload(&raw)?;

    let event = payload.get("hook_event_name").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
    let session_id = payload.get("session_id").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let Some(text) = extract_content(&event, &payload) else {
        // Not an error: SessionStart/Stop/etc. carry nothing worth inspecting.
        return Ok(());
    };

    let rules_path = rules_path();
    let t_stdin_done = Instant::now();
    let db = rules::load(rules_path.to_str().unwrap_or_default()).map_err(|e| format!("loading rules from {rules_path:?}: {e}"))?;
    let t_loaded = Instant::now();

    let report = engine::inspect(&event, &text, &db);
    let t_done = Instant::now();

    log_event(&LogLine {
        ts_unix_ms: now_unix_ms(),
        session_id,
        event,
        content_bytes: text.len(),
        rules_load_us: (t_loaded - t_stdin_done).as_micros() as u64,
        engine_scan_us: report.scan_micros,
        engine_call_us: (t_done - t_loaded).as_micros() as u64,
        harness_total_us: (t_done - t0).as_micros() as u64,
        report,
    })
}

fn parse_payload(raw: &str) -> Result<serde_json::Value, String> {
    serde_json::from_str(raw).map_err(|e| format!("parsing hook JSON: {e}"))
}

/// Mirrors, at a content-shape level, what `cyberhaven-agent-inspector`'s `dlp.rs` would capture
/// for each event -- not byte-for-byte identical (that binary's exact field selection is
/// config-driven per `ContentRule`), but close enough for a detection-parity comparison. Returns
/// `None` for event types with nothing to inspect, which is the common case, not an error.
fn extract_content(event: &str, payload: &serde_json::Value) -> Option<String> {
    match event {
        "UserPromptSubmit" => payload.get("prompt").and_then(|v| v.as_str()).map(str::to_owned),
        "PreToolUse" | "PostToolUse" => {
            let tool_name = payload.get("tool_name").and_then(|v| v.as_str()).unwrap_or("");
            let input_field = if event == "PreToolUse" { "tool_input" } else { "tool_response" };
            let input = payload.get(input_field)?;
            let serialized = serde_json::to_string(input).ok()?;
            Some(format!("{tool_name}\n{serialized}"))
        }
        _ => None,
    }
}

fn rules_path() -> PathBuf {
    if let Ok(p) = std::env::var("CH_SHADOW_RULES") {
        return PathBuf::from(p);
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("rules.json")))
        .unwrap_or_else(|| PathBuf::from("rules.json"))
}

fn log_path() -> PathBuf {
    if let Ok(p) = std::env::var("CH_SHADOW_LOG") {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".ch-inspect-shadow").join("events.jsonl")
}

fn now_unix_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

fn log_event(line: &LogLine) -> Result<(), String> {
    let path = log_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("creating log dir {dir:?}: {e}"))?;
    }
    let json = serde_json::to_string(line).map_err(|e| format!("serialising log line: {e}"))?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("opening log {path:?}: {e}"))?;
    writeln!(f, "{json}").map_err(|e| format!("writing log {path:?}: {e}"))
}

/// Phase 1 of the endpoint impact evaluation ([[endpoint-ci-lab-evaluation-plan]]): aggregate this
/// hook's own JSONL log into latency percentiles, per event type, so the added cost of running
/// local inspection can be read off directly rather than diffed across two noisy live sessions.
/// `rules_load_us + engine_call_us` isolates the marginal cost of local inspection from stdin
/// read time and whatever the real cloud-capture path already does regardless of this hook's
/// presence; `rules_load_us` alone is a fresh-process-per-invocation artifact of this dev harness
/// (a real embedding loads the rule DB once and stays warm, per the module doc), so it's reported
/// separately rather than folded silently into "the cost of local inspection".
#[derive(Default, Clone, Copy)]
struct Sample {
    rules_load_us: u64,
    engine_call_us: u64,
    engine_scan_us: i64,
    harness_total_us: u64,
}

fn percentile(sorted: &[u64], q: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn analyze_log(path: &std::path::Path) -> Result<(), String> {
    let data = std::fs::read_to_string(path).map_err(|e| format!("reading {path:?}: {e}"))?;

    let mut by_event: std::collections::BTreeMap<String, Vec<Sample>> = std::collections::BTreeMap::new();
    let mut parse_errors = 0usize;
    let mut missing_engine_call_us = 0usize;

    for line in data.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => {
                parse_errors += 1;
                continue;
            }
        };
        let event = v.get("event").and_then(|x| x.as_str()).unwrap_or("unknown").to_string();
        let engine_call_us = match v.get("engine_call_us").and_then(|x| x.as_u64()) {
            Some(x) => x,
            None => {
                missing_engine_call_us += 1;
                continue; // pre-instrumentation log line -- excluded, not zero-filled
            }
        };
        by_event.entry(event).or_default().push(Sample {
            rules_load_us: v.get("rules_load_us").and_then(|x| x.as_u64()).unwrap_or(0),
            engine_call_us,
            engine_scan_us: v.get("engine_scan_us").and_then(|x| x.as_i64()).unwrap_or(0),
            harness_total_us: v.get("harness_total_us").and_then(|x| x.as_u64()).unwrap_or(0),
        });
    }

    println!("ch-inspect-claude-hook log analysis: {path:?}");
    if parse_errors > 0 {
        println!("  ({parse_errors} lines failed to parse as JSON -- skipped)");
    }
    if missing_engine_call_us > 0 {
        println!("  ({missing_engine_call_us} lines predate the engine_call_us field -- excluded, not zero-filled)");
    }
    if by_event.is_empty() {
        println!("  no usable samples");
        return Ok(());
    }

    const CEILING_US: u64 = 2_000_000; // the ~2s hook-turnaround ceiling from endpoint-ci-lab-evaluation-plan

    for (event, samples) in by_event {
        let n = samples.len();
        let mut added_latency: Vec<u64> = samples.iter().map(|s| s.rules_load_us + s.engine_call_us).collect();
        let mut engine_call: Vec<u64> = samples.iter().map(|s| s.engine_call_us).collect();
        let mut engine_scan: Vec<u64> = samples.iter().map(|s| s.engine_scan_us.max(0) as u64).collect();
        let mut rules_load: Vec<u64> = samples.iter().map(|s| s.rules_load_us).collect();
        let mut total: Vec<u64> = samples.iter().map(|s| s.harness_total_us).collect();
        added_latency.sort_unstable();
        engine_call.sort_unstable();
        engine_scan.sort_unstable();
        rules_load.sort_unstable();
        total.sort_unstable();

        let over_ceiling = total.iter().filter(|&&us| us > CEILING_US).count();

        println!("\n{event} (n={n}):");
        println!(
            "  rules_load_us      p50={:>6} p90={:>6} p99={:>7} max={:>7}  (fresh-process artifact -- a warm embedding pays this once, not per call)",
            percentile(&rules_load, 0.50),
            percentile(&rules_load, 0.90),
            percentile(&rules_load, 0.99),
            rules_load.last().copied().unwrap_or(0)
        );
        println!(
            "  engine_call_us     p50={:>6} p90={:>6} p99={:>7} max={:>7}  (the actual marginal cost of local inspection, harness-measured)",
            percentile(&engine_call, 0.50),
            percentile(&engine_call, 0.90),
            percentile(&engine_call, 0.99),
            engine_call.last().copied().unwrap_or(0)
        );
        println!(
            "  engine_scan_us     p50={:>6} p90={:>6} p99={:>7} max={:>7}  (same call, engine's own self-reported timer -- gap vs engine_call_us above is harness overhead)",
            percentile(&engine_scan, 0.50),
            percentile(&engine_scan, 0.90),
            percentile(&engine_scan, 0.99),
            engine_scan.last().copied().unwrap_or(0)
        );
        println!(
            "  added (load+call)  p50={:>6} p90={:>6} p99={:>7} max={:>7}  (this dev harness's total added cost; warm-embedding cost = engine_call_us alone)",
            percentile(&added_latency, 0.50),
            percentile(&added_latency, 0.90),
            percentile(&added_latency, 0.99),
            added_latency.last().copied().unwrap_or(0)
        );
        println!(
            "  harness_total_us   p50={:>6} p90={:>6} p99={:>7} max={:>7}  (stdin read + rules load + scan -- full hook wall time)",
            percentile(&total, 0.50),
            percentile(&total, 0.90),
            percentile(&total, 0.99),
            total.last().copied().unwrap_or(0)
        );
        if over_ceiling > 0 {
            println!("  ** {over_ceiling}/{n} invocations exceeded the {CEILING_US}us (~2s) ceiling **");
        } else {
            println!("  0/{n} invocations exceeded the {CEILING_US}us (~2s) ceiling");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn repo_root() -> PathBuf {
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
    }

    #[test]
    fn extracts_the_prompt_from_a_user_prompt_submit_payload() {
        let payload: serde_json::Value = serde_json::from_str(r#"{"hook_event_name":"UserPromptSubmit","session_id":"s1","prompt":"hello there"}"#).unwrap();
        assert_eq!(extract_content("UserPromptSubmit", &payload), Some("hello there".to_string()));
    }

    #[test]
    fn extracts_tool_name_and_input_from_a_pre_tool_use_payload() {
        let payload: serde_json::Value =
            serde_json::from_str(r#"{"hook_event_name":"PreToolUse","session_id":"s1","tool_name":"Write","tool_input":{"content":"x"}}"#).unwrap();
        let text = extract_content("PreToolUse", &payload).unwrap();
        assert!(text.starts_with("Write\n"));
        assert!(text.contains("\"content\":\"x\""));
    }

    #[test]
    fn session_start_and_unknown_events_have_nothing_to_extract() {
        let payload: serde_json::Value = serde_json::from_str(r#"{"hook_event_name":"SessionStart","session_id":"s1"}"#).unwrap();
        assert_eq!(extract_content("SessionStart", &payload), None);
        assert_eq!(extract_content("SomethingNew", &payload), None);
    }

    #[test]
    fn missing_prompt_field_is_none_not_a_panic() {
        let payload: serde_json::Value = serde_json::from_str(r#"{"hook_event_name":"UserPromptSubmit","session_id":"s1"}"#).unwrap();
        assert_eq!(extract_content("UserPromptSubmit", &payload), None);
    }

    #[test]
    fn full_pipeline_round_trips_against_the_real_rules_file_and_matches_a_known_profile() {
        let rules_path = repo_root().join("config/rules.json");
        let db = rules::load(rules_path.to_str().unwrap()).expect("load real rules.json");
        let prompt = "Please store this: card 4111111111111111, SSN 123-45-6789.";
        let report = engine::inspect("UserPromptSubmit", prompt, &db);
        assert!(report.matched(), "expected at least one profile to match: {report:?}");
    }

    #[test]
    fn malformed_json_on_stdin_is_a_reportable_error_not_a_panic() {
        let err = parse_payload("not json").unwrap_err();
        assert!(err.contains("parsing hook JSON"));
    }

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
    fn analyze_log_skips_lines_missing_engine_call_us_without_erroring() {
        let dir = std::env::temp_dir().join(format!("ch-hook-analyze-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl");
        std::fs::write(
            &path,
            "{\"event\":\"UserPromptSubmit\",\"rules_load_us\":100,\"engine_scan_us\":5,\"harness_total_us\":110}\n\
             {\"event\":\"UserPromptSubmit\",\"rules_load_us\":100,\"engine_call_us\":6,\"engine_scan_us\":5,\"harness_total_us\":110}\n\
             not even json\n",
        )
        .unwrap();

        assert!(analyze_log(&path).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn analyze_log_on_a_missing_path_is_a_reportable_error_not_a_panic() {
        let err = analyze_log(std::path::Path::new("/nonexistent/path/events.jsonl")).unwrap_err();
        assert!(err.contains("reading"));
    }
}
