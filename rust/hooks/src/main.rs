//! Non-enforcing Claude Code hook for the lab evaluation of `ch_local_inspect` against the real
//! Cyberhaven client's AI-prompt-security path (`dataflow/Sensors/AI/cyberhaven-agent-inspector`,
//! which today only captures content for async cloud classification -- no synchronous decision).
//!
//! This binary mirrors that capture shape locally: on `UserPromptSubmit`/`PreToolUse` it extracts
//! the same kind of content, inspects it with `ch-inspect-core` directly (no FFI -- this process
//! *is* the integration point, same as any hook written in any other language), and appends one
//! JSONL line per event to a log for later comparison against the same content's eventual cloud
//! incident (detection parity) and against the ~2s latency ceiling a real blocking hook would need
//! (`rules_load_us`/`engine_scan_us`/`harness_total_us` below).
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

fn main() {
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
}
