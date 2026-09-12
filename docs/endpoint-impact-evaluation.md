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
| 2 | Fast file-type scanning | **Done** (calibrated: 300-file Nucleuz run) | `ch-inspect-fs-watch` (`rust/fs-watch`) |
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
    --duration-sec 120 --debounce-ms 300 --sample-interval-sec 1 \
    --max-file-mb 16 --isolate-above-mb 16 --rss-cap-mb 512 --file-timeout-sec 8
```

`--max-file-mb`/`--isolate-above-mb`/`--rss-cap-mb`/`--file-timeout-sec` are configurable per
deployment (see "Per-file isolation + configurable size gate" below) — the defaults shown match
`ch-inspect --scan --isolate`'s.

### Mechanism smoke test (2026-09-11)

Ran end-to-end against a live directory with real file drops — not just unit tests — to confirm
the FSEvents integration actually works: a clean-prose file, a file containing a card number +
SSN, and a 44KB JSON file, dropped in over an 8-second window. Debounce collapsed 11 raw
filesystem events into 3 scans (one per file); detection fired correctly per file; peak RSS
16.4MB, mean CPU 1.4% (8 samples only — a mechanism check, not a calibrated measurement).

### Calibrated run (2026-09-11): 300 real Nucleuz files, 9-minute window

Sourced content from the real Nucleuz DLP policy test corpus (`~/Developer/nucleuz/...`,
external/proprietary, not in this repo) instead of ad-hoc local files, specifically so this run's
detections can eventually be compared against Nucleuz's own Matches/NonMatches ground truth for
efficacy work. 300 files randomly sampled (seed 42) from the full ~3,733-file corpus (mixed
types: txt/pdf/doc/docx/xlsx/odt/images), each copied into the watched directory with a
**traceable flattened filename** (`{index}__{policy}__{Matches|NonMatches}__{original name}`) so
detections can be mapped back to ground truth from the log alone, with no separate mapping file
needed. Dropped one every 1.5s (450s total) into `ch-inspect-fs-watch --duration-sec 540
--sample-interval-sec 1`, giving a ~90s idle tail for catch-up and clean end-of-run sampling.

**Results:**

| Metric | Value |
|---|---|
| Files scanned | 300/300 (0 lost) |
| Unreadable (graceful) | 11/300 — legacy `.doc` (encrypted/legacy format), a few `.png`/`.odt` (unsupported type), one genuine PDF parse panic (see below) |
| Per-file scan latency | mean 38.2ms · p50 10.0ms · p95 69.0ms · p99 362.8ms · **max 4146.4ms** |
| CPU utilization | mean **2.688%** (budget ≤3%) · p99 51.0% · max 171.5% (multi-core burst) |
| Peak RSS | **165.1MB** (budget ≤50MB) |
| fs events seen | 1,532 (≈5.1 raw events per file, all debounced correctly to one scan each) |

**Three real findings, not just "it works":**

1. **A previously-unseen `pdf-extract` panic was caught safely, exactly as designed.**
   `Kenya_Sensitive_Data/NonMatches/SampleFile_Genetic_001.pdf` hit
   `Content::decode(&content).unwrap()` (`vendor/pdf-extract/src/lib.rs:1616` — pre-existing
   upstream code, not something the fixes in `PATCH.md` touched) on a stream that failed to
   parse (`Parse(InvalidContentStream)`). `core/src/extract.rs`'s `catch_unwind` boundary caught
   it: the file was reported `readable: false` with a note, the watcher process kept running,
   and all 300 files completed normally (exit 0). The panic message still prints to stderr by
   Rust's default panic hook even though it's caught — cosmetic, but worth knowing so it isn't
   mistaken for an actual crash when watching the log live.
2. **Peak RSS (165.1MB) confirms the already-documented residual, now in this specific
   companion, for the first time.** The slowest file — `Colombia_PII/Matches/
   SampleFile_BankAccountNumber_001.pdf` (5.4MB), 4.1 *seconds* to scan — is the same file
   already identified in `rust/vendor/pdf-extract/PATCH.md`'s "Residual ~9% investigated
   further" section (the struct-tree-heavy, `lopdf`-object-graph-load case). 165MB is *higher*
   than that file's own previously-measured ~85-87MB, consistent with the also-already-documented
   Mechanism B (allocator page retention across a long-lived process handling many sequential
   files) compounding on top of it here, in a genuinely warm, sustained process for the first
   time. This isn't a new bug — it's the documented, accepted limitation showing up exactly
   where it was predicted to.
3. **CPU margin is thinner on realistic content than the earlier smoke test suggested.** Mean
   2.688% against a 3% budget is a real pass, but a much narrower margin than the 8-file smoke
   test's 1.4% — driven by the corpus's natural mix including a handful of slow, large PDFs.
   Worth re-checking if the real drop rate on an actual endpoint turns out faster than 1 file/1.5s.

**Traceability check (not a scored efficacy metric — that comparison is Ben's separate effort
against the labeled corpus):** of the 154 sampled files under a `Matches` ground-truth directory,
99 (64.3%) fired at least one profile; of 132 under `NonMatches`, 66 (50.0%) fired at least one.
This is a coarse "any profile at all" heuristic, not a per-policy precision/recall score (this
engine's profile taxonomy doesn't map 1:1 to Nucleuz's per-policy definitions, and the rigorous,
already-completed recall work in `nucleuz-recall-validation` found ~19.6% on proper per-policy
scoring) — it only confirms detection isn't obviously broken and that the flattened-filename
scheme successfully preserves ground truth for whoever runs the real comparison.

### Per-file isolation + configurable size gate (2026-09-12)

Prompted by a real question: on-prem file sizes can exceed what's been tested so far, and the
size gate needed to be configurable. Investigating surfaced a fact worth being explicit about —
**`--max-file-mb` (the extraction-layer size gate) does not bound PDF/OOXML parsing cost at
all.** It only truncates plaintext files and the *extracted text* from PDF/OOXML after
`pdf-extract` has already fully parsed the document (confirmed in `core/src/extract.rs`). So
raising it does nothing for the known large-PDF residual RSS issue documented in
`vendor/pdf-extract/PATCH.md`. Simply raising the gate for "bigger on-prem files" would have been
the wrong fix.

Instead, ported `cli/src/scan.rs`'s `--scan --isolate` mechanism — the same one already proven
against the real PDF-bomb class — into `fs-watch`: **files at or above `--isolate-above-mb`
now run in a child process with an RSS-cap + timeout watchdog** (`--rss-cap-mb`,
`--file-timeout-sec`), so a large or pathological file can only kill its own child, not the
watcher. Smaller files still run in the fast, warm, in-process path Phase 1/2 was originally
measured with — this only changes behavior for files above the threshold. `--max-file-mb` is now
also configurable here (previously hardcoded via `extract::Config::default()`).

Validated end-to-end with real runs, not just unit tests (the isolation mechanism can't be
meaningfully unit-tested — `std::env::current_exe()` resolves to the test harness binary under
`cargo test`, not a binary that understands `--rules`/`--file`, the same limitation `--scan
--isolate` already has):
- A 36-byte file stayed in-process (`isolated: false`); a 3.8MB file (threshold set to 1MB)
  correctly ran isolated (`isolated: true`) and still detected PCI/PII correctly.
- The already-known slow Colombia PDF (~4.1s to scan, see the calibrated-run findings above),
  run against a 1-second timeout, was correctly killed by the watchdog after ~1.14s
  (`killed: true`, no `report` field) — and the watcher process itself kept running cleanly
  through its full duration afterward.
- A real integer-overflow bug was caught during this work: the size-threshold check
  (`isolate_above_mb * 1MB`) overflowed `u64` when a caller passed `u64::MAX` to mean "never
  isolate," panicking on every file. Fixed with `saturating_mul`; now covered by a unit test.

### Open items

1. **`--watch-dir` target still not decided.** Needs to point at whatever directories actually
   matter on the real endpoint (Downloads/Desktop, or wherever the real Swift `ContentScanner`
   would trigger) — runs so far used an arbitrary test directory.
2. Recursive watching, debounce tuning, and hidden-file handling are implemented but not yet
   tuned against real usage patterns.
3. Isolation adds real overhead per large file (process spawn + a fresh rules load, ~17-20ms per
   Phase 1's measurement) — fine given it only applies above the threshold, but worth remembering
   if `--isolate-above-mb` is set very low.

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

The calibrated 300-file Nucleuz run's drop script (`phase2_calibrated_drop.py`) isn't committed
to this repo — it's a one-off harness against the external/proprietary Nucleuz corpus path, same
convention as the earlier `pdf-extract` survey scripts in `PATCH.md`. To re-derive it: sample N
files (seeded, for reproducibility) from the corpus root, copy each into the watched directory
as `{index}__{policy}__{Matches|NonMatches}__{original name}` (preserves ground truth in the
filename for later analysis), sleeping a fixed interval between copies, while
`ch-inspect-fs-watch` runs concurrently with `--duration-sec` comfortably longer than the total
drop time (drop time + ~20% buffer worked well here).

Both tools are read-only with respect to the content they inspect (they never write to or modify
watched files/directories) and both fail closed — a hook error never blocks a Claude Code turn,
a watch error is logged and skipped, and an extraction panic (see the calibrated run's findings
above) is caught by `extract.rs`'s `catch_unwind` boundary rather than crashing the process.

## Next steps

1. Add a per-file timeout/kill-switch to `ch-inspect-fs-watch`, mirroring `--scan --isolate`'s
   RSS/time watchdog — the calibrated run has no cap today.
2. Decide the real `--watch-dir` target(s) for this use case on the actual endpoint.
3. Build Phase 3 (clipboard companion).
3. Efficacy comparison (local vs. cloud vs. labeled corpus) — being run separately, outside this
   codebase; not tooling built here.
