# Endpoint impact evaluation (lab, macOS)

Whether `ch_local_inspect` can run on a real endpoint alongside the actual Cyberhaven client —
and what it costs to do so — across two kinds of use case: fast file-type scanning ("quick
decisions" on file content) and interactive surfaces (copy/paste, AI-agent prompts, and other
similar paths). This is a live evaluation on a real macOS lab machine, not a synthetic-corpus
benchmark — see `../CLAUDE.md`'s resource budget (≤50MB peak RSS, ≤3% sustained CPU) for the
numbers being checked against.

**Explicitly out of scope for this document/harness:** detection *efficacy* (local vs. cloud vs.
a labeled ground-truth corpus). That comparison is being run separately, outside this codebase,
against a labeled corpus. Everything here is about **added latency and resource impact** —
does running local inspection alongside the real client cost anything worth worrying about.

## Approach: a non-enforcing companion process, not code injected into the real client

The obvious way to measure "impact of running local inspection on the endpoint" would be to
inject `ch-inspect-ffi` directly into the real content-scanning code and diff performance
before/after. That's not what's done here, for a concrete reason: the real per-platform
scanners are **not Rust**.

- Windows: C#/.NET (`Sensors/Endpoint/ContentScanner`, `.../DocumentScanner`)
- macOS: Swift (`Sensors/MacOS/ContentScanner`)
- Linux: a separate C/C++ repo (`sentinel`)

The only Rust code in the real sensor estate is the AI-prompt-security path
(`dataflow/Sensors/AI/cyberhaven-agent-inspector`), which today does pure fire-and-forget cloud
capture with no local decision logic at all.

Embedding `ch-inspect-ffi` into any of the three real scanners for a lab experiment means real
per-platform FFI work (P/Invoke, a Swift bridging header, native linking) inside production
sensor code, for something that's meant to be a fast comparison. **Instead, every phase below is
a separate, non-enforcing companion process** that watches for the same kind of trigger event the
real client would see (a hook event, a file write, eventually a clipboard change) and
independently calls `ch-inspect-core`/`ch-inspect-ffi` on that content — touching none of the
real scanners.

This has a useful consequence for measurement: because each companion is its own process, its
own CPU/RSS footprint during a run **is** the complete "additional impact of running the scan on
the endpoint" — there's nothing else on the endpoint for its presence to have slowed down. That
means no noisy live baseline-vs-treatment A/B across two time windows is needed; the tool's own
resource usage, measured directly, is the answer.

| Phase | Use case | Status | Companion |
|---|---|---|---|
| 1 | AI-agent prompts (Claude Code hooks) | **Done** | `ch-inspect-claude-hook` (`rust/hooks`) |
| 2 | Fast file-type scanning | **Done** (smoke-tested; not yet calibrated) | `ch-inspect-fs-watch` (`rust/fs-watch`) |
| 3 | Copy/paste | Not started | planned: clipboard-change poller |

## Phase 1 — AI-prompt hook (`rust/hooks`)

Registered alongside Claude Code's real hooks (`UserPromptSubmit`, `PreToolUse`) in
`~/.claude/settings.json`, pointing at `~/.ch-inspect-shadow/bin/ch-inspect-claude-hook`. On each
event it extracts the same content Cyberhaven's own `dlp.rs` would, inspects it directly via
`ch-inspect-core` (no FFI — this process *is* the integration point), and appends one JSONL line
per event to `~/.ch-inspect-shadow/events.jsonl`.

**What's measured, per invocation:**
- `rules_load_us` — cost of loading `rules.json`. This binary is a fresh process per hook
  invocation (Claude Code's own contract), so this is paid every call; a real warm embedding
  would load once and never pay it again.
- `engine_call_us` — harness-measured wall-clock for the `engine::inspect` call itself, isolated
  from stdin-read and rules-load overhead. **This is the actual marginal cost a real, warm
  embedding would attribute to running local inspection.**
- `engine_scan_us` — the engine's own self-reported timer for the same call (a gap between this
  and `engine_call_us` would be harness overhead, not engine cost).
- `harness_total_us` — full wall time Claude Code would experience (stdin read + rules load +
  scan).

Run `ch-inspect-claude-hook --analyze [path]` (default: the live log) to aggregate the log into
per-event latency percentiles. Real Claude Code hook invocations never pass args, so `--analyze`
can only be reached by a deliberate manual invocation.

### Results (2026-09-11)

A repeatable synthetic batch (90 invocations — `UserPromptSubmit`/`PreToolUse`, content sizes
50B–50KB, seeded) rather than waiting on organic traffic:

| Metric | p50 | p90 | p99 |
|---|---|---|---|
| `engine_call_us` (true marginal cost) | 400–620µs | ~3.2ms | ~3.3–3.5ms |
| `rules_load_us` (fresh-process artifact) | ~17–18ms | ~19ms | ~20–32ms |
| `harness_total_us` (worst-case total) | ~18.7–18.8ms | ~20–21ms | ~22–32ms |

0/90 invocations came anywhere near the ~2s hook-turnaround ceiling (Ben's estimate of the
maximum latency injectable into a Claude Code conversation turn — not a documented platform
timeout, worth verifying directly if this becomes load-bearing). Even the *worst-case* shape
(fresh rules-load every call) is two orders of magnitude under budget; the real embedded cost
(`engine_call_us` alone, once warm) is sub-millisecond to a few milliseconds.

**Conclusion: local inspection adds no meaningful latency to this path.** This doesn't need
re-measuring unless the engine's own scan cost changes materially.

## Phase 2 — filesystem-watch companion (`rust/fs-watch`)

`ch-inspect-fs-watch --watch-dir <dir>` loads the rules DB once and stays warm for the whole run
(the realistic embedded-sensor shape, unlike Phase 1's fresh-process-per-invocation constraint),
watches a directory via the OS's native file-watching API (`notify` crate, FSEvents backend
confirmed on this macOS lab endpoint), debounces per-path write events (waits for a quiet period
after the last write before scanning, so a file isn't scanned mid-write), and logs one JSONL
line per scanned file to `~/.ch-inspect-shadow/fswatch_events.jsonl`.

**What's measured:**
- Per-file scan latency (mean/p50/p95/p99/max).
- CPU utilization, sampled on a fixed interval (same methodology as `--cpu-soak` in
  `rust/cli/src/soak.rs`, applied to real filesystem events instead of a synthetic loop).
- Peak RSS for the whole run.
- A pass/fail line against the `<=3% CPU` budget.

```
ch-inspect-fs-watch --rules config/rules.json --watch-dir <dir> \
    --duration-sec 120 --debounce-ms 300 --sample-interval-sec 1
```

### Validation (2026-09-11)

Ran end-to-end against a live directory with real file drops — not just unit tests — to confirm
the FSEvents integration actually works: a clean-prose file, a file containing a card number +
SSN, and a 44KB JSON file, dropped in over an 8-second window.

- **Debounce worked correctly**: 11 raw filesystem events collapsed into exactly 3 scans (one per
  file), each scanned once its writes had quiesced.
- **Detection fired correctly**: clean file → no profiles; card+SSN file → PCI + PII; the 44KB
  file → PCI/PII/Secrets/Source-code (plausible for a JSON file this size with varied literal
  content).
- **Measured footprint**: peak RSS 16.4MB (budget ≤50MB), mean CPU 1.4% (budget ≤3%) — both
  comfortably within budget, on a real run on this endpoint.

### Open items — this is a validated mechanism, not yet a calibrated measurement

1. **Only an 8-second, 3-file smoke test so far.** The actual number worth reporting (comparable
   to Phase 1's 90-invocation batch) needs a longer run driven by a **repeatable synthetic
   file-drop** — a scripted sequence of real corpus files dropped at a controlled rate — rather
   than a handful of ad-hoc files, to get stable latency/CPU percentiles instead of an
   8-sample window.
2. **`--watch-dir` target not yet decided.** Needs to point at whatever directories actually
   matter for this use case on the real endpoint (e.g. Downloads/Desktop, or wherever the real
   Swift `ContentScanner` would trigger) — currently an arbitrary directory for testing purposes.
3. Recursive watching (`--recursive`), debounce tuning, and hidden-file handling are implemented
   but not yet tuned against real usage patterns.

## Phase 3 — clipboard companion (not started)

Planned: same non-enforcing companion pattern, triggered by clipboard changes instead of file
writes. macOS has no push notification API for clipboard changes — `NSPasteboard.changeCount`
polling (checking whether the count has incremented since last checked, typically every 200–
500ms) is the standard technique clipboard-monitoring tools use. Lower priority than Phase 2;
not yet scoped in code.

## Reproducing these results

```bash
# Phase 1: aggregate the live hook log (or a batch log) into latency percentiles
~/.ch-inspect-shadow/bin/ch-inspect-claude-hook --analyze ~/.ch-inspect-shadow/events.jsonl

# Phase 2: watch a directory for a fixed duration and report CPU/RSS/latency
cd rust && cargo build --release -p ch-inspect-fs-watch
./target/release/ch-inspect-fs-watch --rules ../config/rules.json \
    --watch-dir <dir> --duration-sec 120
```

Both tools are read-only with respect to the content they inspect (they never write to or modify
watched files/directories) and both fail closed — a hook error never blocks a Claude Code turn,
and a watch error is logged and skipped, never a panic.

## Next steps

1. Run Phase 2 as a proper calibrated measurement (synthetic file-drop sequence, longer duration)
   rather than the current smoke test, once the target watch directory/directories are decided.
2. Build Phase 3 (clipboard companion).
3. Efficacy comparison (local vs. cloud vs. labeled corpus) — being run separately, outside this
   codebase; not tooling built here.
