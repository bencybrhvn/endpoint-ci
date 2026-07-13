# Architectural Decision Log

Each entry: **Context** (why) · **Decision** (what) · **Alternatives** · **Consequences**.

---

## 2026-06-24 — Implement in Go, not the spec's C

**Context:** `overview.md` specifies a C library (`ch_local_inspect`) using RE2, MuPDF, and miniz under CMake. This is a PoC whose goal is correctness + measurability of a resource budget, with fast iteration valued.

**Decision:** Build the PoC in **Go 1.26**, keeping every concept and the public behaviour of the spec (rule reuse, compatibility classification, ALLOW/BLOCK/ESCALATE verdicts keyed to `dataset_id`, the budget). Diverge from the spec's C-level API surface.

**Why this is sound, not a shortcut:**
- Go's standard-library `regexp` **is an RE2 implementation** — the spec's central RE2 compatibility model is native, with no cgo. `regexp.Compile` succeeding/failing *is* the LOCAL_CAPABLE vs CLOUD_ONLY test.
- OOXML extraction (DOCX/XLSX/PPTX) is `archive/zip` + `encoding/xml` in stdlib — no miniz needed.
- Single static binary; trivial cross-compile to macOS/Linux; fast iteration.

**Alternatives considered:**
- *C as specified* — max fidelity and closest to the production sensor, but heavy deps (RE2/MuPDF submodules) and slow iteration for a PoC.
- *Hybrid (Go prototype → port to C)* — viable later if footprint demands it.

**Consequences:**
- PDF text extraction has no MuPDF; v2 uses a Go PDF text library (e.g. `ledongthuc/pdf`) or defers PDF.
- GC and binary size must be watched against the ≤50 MB / ≤3% CPU budget via benchmarks.
- If the validated design must ship in the native sensor, port the proven approach to C/Rust later.

---

## 2026-06-24 — Rule reuse is the architecture (per spec §2)

**Context:** Maintaining separate cloud and local rule sets would diverge and cause unexplainable detection discrepancies.

**Decision:** Consume the cloud-side rules file as **read-only** input. `dataset_id`/`rule_id` pass through unmodified to verdicts; every match is tagged `scan_path: "local"`. Never silently drop a rule — `CLOUD_ONLY` rules always surface in the compatibility report with a specific reason.

**Consequences:** Local and cloud verdicts on identical content are directly comparable; rewrite-induced semantic drift is detectable. The compiler, not a hand-written detector set, is the heart of the system.

---

## 2026-06-24 — Build order: thin vertical slice first

**Context:** Heavy formats (PDF) add dependency weight before any measurable result.

**Decision:** v0 = plaintext/CSV end-to-end (load rules + compat report + scan + validators + verdict + consistency test + latency benchmark). v1 = OOXML (archive/zip). v2 = PDF text layer + full label paths.

**Consequences:** Fastest path to a measurable, comparable result that proves the rule-reuse architecture before investing in format breadth.

---

## 2026-06-24 — WASM browser demo

**Context:** Evaluate running the engine in a browser extension.

**Decision:** Compile the engine core to WebAssembly (`GOOS=js GOARCH=wasm`). Added
filesystem-free entrypoints — `rules.LoadBytes(rulesJSON, lexicons)` and
`engine.InspectData(name, data, …)` — so the WASM layer (`cmd/wasm`, `//go:build js
&& wasm`) feeds rules + file bytes from JS. A static demo (`web/`) loads the rules,
accepts a dropped file / pasted text, and shows the verdict. Verified end-to-end
headlessly via Node (correct verdicts for txt/docx/pdf).

**Why it works:** pure Go, one pure-Go dependency, no cgo; `regexp`/`archive/zip`/
`encoding/xml`/`flate` all run in WASM. `os/exec`/`syscall` live only in the CLI
profiler, not the engine. Output ~5.2 MB raw / 1.5 MB gzipped.

**Consequences / constraints:** single-threaded in-browser (`NumCPU`→1; parallel
scan is a no-op, fine for small files). Rules stay external (fetched by JS), keeping
them tunable. Build artifacts are git-ignored; `web/build.sh` regenerates them.

**2026-06-24 update — Web Worker isolation (implemented):** the engine now runs in a
Web Worker (`web/worker.js`); the page inspects each file with a timeout and
**terminates + respawns the worker** on overrun — the browser equivalent of per-file
process isolation for the PDF DoS. Required making `chInspect` **async (return a
Promise)**: a synchronous JS→WASM call never yields to the event loop, so a blocking
syscall inside it (e.g. `ledongthuc/pdf`'s unconditional `DEBUG` stdout write)
deadlocks Go's single-threaded WASM scheduler. Verified: full Nucleuz corpus incl.
all 1,457 PDFs completes (~142 s); the 24 memory-bomb PDFs are isolated rather than
OOM-crashing; 99.7% verdict parity with native (the ~0.3% are slow PDFs the tight
1.5 s worker timeout isolated but native finished at 8 s).

---

## 2026-06-24 — Real-world profiler + PDF DoS isolation

**Context:** Profiling against real files (a 3,735-file labelled policy corpus) to measure latency/impact surfaced a serious robustness issue.

**Findings & decisions:**
- **`--scan` profiler** added: recursive, latency percentiles, throughput, verdict/type breakdowns, slowest files, heap + peak RSS, `--csv`/`--cpuprofile`/`--memprofile`; dot-dirs skipped by default.
- **PDF DoS:** ~24/1,457 PDFs made `ledongthuc` allocate multi-GB *live* memory (peak 9.5 GB) → OOM. `GOMEMLIMIT` didn't help; in-process guards can't stop it. **Decision: process isolation** — `--scan --isolate` (default on) runs each file in a child with an RSS cap + timeout watchdog; a bomb only kills the child (→ ESCALATE), parent stays ~17 MB. Production must sandbox untrusted PDF/text extraction (separate process / resource-limited build), as the spec's controlled-MuPDF approach implied.
- **Unsupported vs encrypted:** plain binary/unsupported types → **ALLOW** (no text, not our content); only encrypted/corrupt → **ESCALATE**. (Previously everything unreadable escalated, which floods on real machines.)
- **Single-signal types:** lone IP/email don't BLOCK (no profile for one weak signal) — documented; add a standalone profile if needed.

**Consequences:** the engine can safely profile arbitrary real files. Accuracy on implemented data types is ~100% recall on the corpus; lower overall only because the corpus spans policies outside MVP scope.

---

## 2026-06-24 — Size gate + head/tail extraction

**Context:** A multi-MB/GB file shouldn't be fully inspected inline on the endpoint hot path (spec §4.3).

**Decision:** `extract.Config` gains `MaxFileBytes` (gate, default 16 MB; CLI `--max-file-mb`) and `HeadTailWindow` (default 64 KB). Over the gate, only the head + tail windows are inspected and the result is flagged `Partial` (plaintext gated on raw bytes to avoid building a huge string). The verdict is **coverage-aware**: a `Partial`/`Truncated` result that is otherwise clean → **ESCALATE**, not ALLOW (the unseen middle must not be silently passed). Profiles/labels firing in the head/tail still BLOCK; the metadata label path always runs on the full container (docProps are tiny).

**Consequences:** cost is bounded regardless of file size (21 MB file → 131 KB inspected, ~18 ms). The trade-off is the middle of very large files isn't scanned locally — surfaced as ESCALATE for cloud/heavier inspection, exactly the intended hand-off.

---

## 2026-06-24 — OOXML sensitivity-label fast-path

**Context:** Sensitivity labels (MS MIP/AIP, custom org markings) are a high-value, cheap signal that doesn't need full content inspection (spec §4.5).

**Decision:** `internal/label` with two paths, driven by a `label_markers` section in rules.json:
- **Metadata fast-path** — open the OOXML zip and read *only* `docProps/custom.xml`+`core.xml`; match property names against `metadata_properties` (MSIP_Label/Sensitivity/Classification/DataClass) and values against label strings. Runs on raw bytes in `InspectFile` before/around extraction. Machine-written ⇒ authoritative ⇒ upgrades verdict to **BLOCK**.
- **Body fallback** — scan extracted text for *distinctive* markings only (multi-word or all-caps, case-sensitive) so "Confidential" in prose doesn't trip it ⇒ at least **ESCALATE**.

Verdict gains `labels[]` (with `source`). Disposition uses a severity upgrade (BLOCK>ESCALATE>ALLOW) so labels combine cleanly with profile verdicts.

**Consequences:** a labelled-but-otherwise-clean document is now caught (metadata→BLOCK) with negligible cost (no body scan needed). Body markings are deliberately conservative to limit FPs.

**2026-06-24 update — PDF XMP:** extended the metadata fast-path to PDF. We locate the XMP packet (`<?xpacket…?>`) in the raw bytes and match property names (with separator/case normalisation, so `msip:Label` matches the `MSIP_Label` cue) + label-string values. The fast-path now runs in `InspectFile` even when text extraction *fails*, so a labelled-but-unparseable PDF still BLOCKs (was previously a plain ESCALATE). Limitation: compressed XMP metadata streams aren't decoded (MSIP/AIP keep XMP uncompressed in practice).

---

## 2026-06-24 — Tier-2 detectors + early-exit short-circuit

**Context:** Broaden coverage (US+UK Tier-2) and let the engine stop once a verdict is decided.

**Decision — Tier-2 detectors:** added `us_itin` (validator `itin_check`), `us_drivers_license` (best-effort, keyword-gated), `us_medicare_mbi` (HIPAA health), `uk_drivers_license`. Added a **UK_PII profile** mirroring US_PII — this also activates the already-present `uk_nino`/`uk_passport`/`uk_utr`, which previously fed no profile. Now 31 detectors, 6 profiles, still all LOCAL_CAPABLE.

**Decision — early-exit:** evaluate detectors in priority-ordered batches (validator-backed/strong first); after each batch re-evaluate profiles and stop once a BLOCK-confidence verdict is reached, or once `max_total_matches` is crossed. The disposition can't change after BLOCK, so remaining detectors are pure cost (allocs dropped ~65× on saturated input).

**Consequences:** a short-circuited verdict is **disposition-correct but may list a partial set of profiles** (we stopped once it was clearly bad — the requested behaviour). Detection-completeness tests therefore run with early-exit disabled; the fast path is asserted separately (`TestEarlyExit`). `us_drivers_license`'s generic shape is FP-prone → kept best-effort + keyword-gated + low confidence.

---

## 2026-06-24 — Multi-pattern matcher to hit the 500KB latency budget

**Context:** Naive per-detector scanning ran ~2.8 MB/s → a 500 KB file took ~185 ms, ~1.8× over the <100 ms target.

**Decision:** Four layered, semantics-preserving optimisations (see docs/engine-notes.md):
1. **Aho-Corasick literal prefilter** (`internal/prefilter`) — one pass marks which literal cues are present; literal-anchored detectors with no cue are skipped. Plus a `needs_digit` gate.
2. **Match cap (64)** — `FindAllStringIndex` stops early; we never need all matches to satisfy a profile.
3. **Parallel detector scan** — independent read-only detectors run across `NumCPU` goroutines.
4. (kept) best-effort keyword gating + per-detector pattern combine.

Result: ~17 MB/s. 500 KB dense ~31 ms, 500 KB prose+PII ~33 ms, typical ≤8 KB ~0.7 ms — all within budget. Race-clean.

**Rejected:** a single mega-regex (all detectors in one alternation) — overlapping detectors steal each other's matches (ABA's `\d{9}` ate NPI digits → HIPAA stopped firing) and it was slower. RE2 set-matching gives membership, not all per-pattern positions.

**Consequences:** counts saturate at the cap (fine for our thresholds); parallelism trades a brief CPU burst for latency (the ≤3% CPU budget is amortised over an event stream); a true vectorised matcher (Hyperscan) remains the production path for pathological inputs.

---

## 2026-06-24 — Extraction: stdlib for OOXML, ledongthuc/pdf for PDF

**Context:** The engine needs to inspect real documents (DOCX/XLSX/PPTX/PDF), not just plaintext. The spec's C design used miniz + MuPDF.

**Decision:** OOXML via the Go standard library (`archive/zip` + a tag-stripping pass over the text-bearing parts) — no third-party dep. PDF text layer via `github.com/ledongthuc/pdf` (pure Go, MIT) — the one external dependency, chosen over cgo/MuPDF to keep the PoC a single static binary.

**Consequences:**
- OOXML extraction is dependency-free and fast.
- PDF text extraction covers standard text-layer PDFs; it won't handle scanned/OCR, complex CMaps, or encrypted PDFs — those degrade to ESCALATE. `ledongthuc/pdf` can panic on malformed input, so the extractor wraps it in a recover and fails to ESCALATE, never crashing.
- Encrypted/legacy OLE files (`D0 CF 11 E0`) are detected and ESCALATEd, not parsed (spec scope excludes them).

---

## 2026-07-07 — Report matches, don't decide actions (remove ALLOW/BLOCK/ESCALATE)

**Context:** The spec (§4.6) and the early PoC had the engine emit an ALLOW/BLOCK/ESCALATE *verdict*, with per-profile `verdict_on_match` ceilings and a `block_threshold`. In the real product the action decision is **not** made by this component — a separate policy engine consumes detections and decides enforcement. Baking actions into the inspection engine conflates two layers and uses the wrong vocabulary (a content inspector doesn't "block").

**Decision:** The engine **inspects and reports only**. It emits a match `Report`, never a verdict/action:
- Removed the `Disposition` (ALLOW/BLOCK/ESCALATE) and the `Allow`/`Block`/`Escalate` constants.
- Removed `verdict_on_match` from every profile and the severity-upgrade logic. A profile is just a named concept + `data_type`; each match reports `confidence` and the contributing leaf `rules` (rule_ids) as evidence.
- Renamed the confidence-model knob `block_threshold` → `high_confidence_threshold` and the early-exit trigger `stop_on_block` → `stop_on_high_confidence`. These now serve **reporting quality** (flagging strong matches) and the **hot-path cost optimisation** — not an action.
- States that were previously encoded as ESCALATE are now **neutral scan facts** the policy layer weighs: `readable: false` (encrypted/corrupt/binary — no body inspected) and `coverage: full|partial|truncated` (size gate / cap). The unsupported-vs-encrypted distinction survives only as a `note`.
- Sensitivity labels are reported in `labels[]` with their `source` (metadata vs body); the engine no longer upgrades anything on their account.

**Alternatives considered:**
- *Keep `verdict_on_match` as an advisory hint* — rejected: it re-introduces action vocabulary into a component that must not own the decision, and invites drift with the real policy engine.
- *Emit raw evidence with no confidence* — rejected (see below): throws away the validator/keyword/instance scoring the engine already does well; we chose to keep `confidence` + a `fired`/high-confidence flag as a detection-quality signal, distinct from the action.

**Consequences:**
- Output contract changed: `Report{ readable, coverage, profiles[]{confidence, rules[]}, labels[], detectors[]{data_types…} }`. `DetectorFinding` now carries `data_types` (dataset_id pass-through) to preserve cloud comparability.
- CLI `--scan` summary reports clean/matched/high-confidence/unreadable counts instead of verdict counts; the WASM demo badge shows NO MATCH / MATCH / UNREADABLE / ISOLATED.
- This **deviates from `overview.md` §4.6** deliberately; the spec's verdict logic is superseded by this entry. Early-exit still trims the reported profile set on strong matches (flagged `short_circuited`).

---

## 2026-07-08 — Source-code detection as a scoring detector kind

**Context:** DLP needs to flag source code (IP egress), but source code has **no checksum** — the regex+validator model behind PCI/SSN doesn't apply. It's a fuzzy classification problem.

**Decision:** Add a third detector `kind: "code"` alongside `regex` and `dictionary`, mirroring the person-name scorer: a language-agnostic classifier (`scanCode` in internal/scan) that combines corroborating evidence families — keyword/operator density, structural punctuation, indentation, and comment-line fraction — penalises natural-language prose, and requires a minimum absolute keyword count before it can fire. All weights + token sets live in `config/rules.json` under the detector's `code` block, so calibration needs no recompile. Feeds a `SOURCE_CODE` profile (`DT_Source_Code`). One O(n) line pass + a token-count pass; a 500 KB source file inspects in ~20 ms / 43 allocs.

**Calibration — validated against the Nucleuz corpus's own `Intellectual_Property/Matches/` source samples (14 languages), which is held-out ground truth (calibration used a separate synthetic set):** initial recall was only 5/14. Two failure modes — invisible in the synthetic set — drove the design:
- **Comment prose.** Real source opens with big English **licence / doc-comment blocks** (the MD5 C licence, a Python API-builder header). Treating comment lines as prose penalised real code into silence. Fix: comment lines (leading `//`, `/*`, `*`, `#`, `--`, `!`, `;`, docstring delims) are **positive** evidence, never prose.
- **Line-structure loss on extracted documents.** `.docx`/`.pdf` extraction concatenates paragraphs into a few very long lines, which exploded per-line keyword density and made a Māori-language article score 95. Fixes: normalise density by an **estimated logical-line count** (`max(lines, words/12)`), and detect prose by **symbol density** (long word-runs with ≤2 code symbols) rather than a terminal full stop (extraction strips it).

**Result:** **10/14** recall on the real source files (75–95 confidence; Perl, C#, Fortran, SQL all fire despite not being in the calibration set) and **0 false positives across all 2,278 non-PDF corpus files** — including legal/government prose with 100+ "public" hits and long prose articles. Residual misses: a 2-line Bash stub (below `min_lines`) and three licence-/data-dominated files.

**Consequences / headroom:** the classifier is strongest on raw code files/paste (real line structure); extracted document prose is guarded by the logical-line + symbol-density + comment fixes. The `source_code` detector runs `strings.Count` over ~68 tokens for every file — within budget, but a future optimisation is to fold those into the Aho-Corasick prefilter and skip the scorer when no code keyword is present. Secrets detection (`api_key`/`private_key`/`jwt` → `SECRETS`) is the complementary regex+prefix capability and already existed.

---

## 2026-06-24 — Open: negative-lookahead PII patterns

**Context:** The spec's sample SSN pattern uses negative lookaheads `(?!000|666|9\d{2})`, which strict RE2 (and Go `regexp`) reject.

**Decision (provisional):** Classify such patterns `CLOUD_ONLY` by default. Revisit a semantic range-rewrite to `LOCAL_APPROXIMATE` once the **real** rules file is available and we know how prevalent lookaheads are.

**Consequences:** Initial local coverage may exclude some structured-PII rules; the compatibility report will make the gap explicit and quantified.

---
