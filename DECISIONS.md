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

## 2026-06-24 — Open: negative-lookahead PII patterns

**Context:** The spec's sample SSN pattern uses negative lookaheads `(?!000|666|9\d{2})`, which strict RE2 (and Go `regexp`) reject.

**Decision (provisional):** Classify such patterns `CLOUD_ONLY` by default. Revisit a semantic range-rewrite to `LOCAL_APPROXIMATE` once the **real** rules file is available and we know how prevalent lookaheads are.

**Consequences:** Initial local coverage may exclude some structured-PII rules; the compatibility report will make the gap explicit and quantified.

---
