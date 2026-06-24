# CLAUDE.md — endpoint-ci (`ch_local_inspect`)

> Project context and working guidelines for Claude Code. Read this first, then `overview.md` (the build spec).

## Project

- **Name:** endpoint-ci — local content inspection PoC (library name: `ch_local_inspect`)
- **Description:** A self-contained, offline content inspection engine that runs **on the endpoint**. It ingests Cyberhaven's **existing cloud-side content inspection rule definitions** (datasets), compiles them into a local pattern database, and returns a structured verdict (ALLOW / BLOCK / ESCALATE) for a file — using the **same `dataset_id`s as the cloud**, so local and remote verdicts are directly comparable.
- **Authoritative spec:** `overview.md` ("Endpoint Content Inspection — PoC Build Specification"). When in doubt, the spec wins; this file captures decisions and working notes on top of it.
- **Stack:** **Go 1.26** (single static binary). See DECISIONS.md for why Go over the spec's C.
- **Target audience:** Cyberhaven engineering & product (internal PoC).
- **Status:** Early PoC — building v0 thin slice.
- **User technical level:** Domain Expert (product/security), pairing with Claude.
- **Language preference:** British English.
- **Last updated:** 2026-06-24.

## The core principle: rule reuse

The single most important design constraint (spec §2): **cloud and local inspection share one rule source.** We never maintain a second rule set.

- The rules file (datasets + `label_markers`, see spec §5) is **read-only input**. We do not modify, redefine, or re-ID patterns.
- `dataset_id` and `rule_id` pass through **unmodified** from input rules into the output verdict.
- Every match carries `scan_path: "local"` so downstream can compare against a cloud re-scan. Drift on the same content signals a pattern-rewrite changed semantics.

## Why Go works for the RE2 compatibility story

The spec is built around RE2 (no lookaheads/lookbehinds/backreferences). **Go's standard-library `regexp` package *is* an RE2 implementation.** So:

- `regexp.Compile(pattern)` **succeeding** ⇒ `LOCAL_CAPABLE`.
- It **failing** on `(?=)`, `(?<=)`, `(?<!)`, `\1` ⇒ candidate `CLOUD_ONLY` (capture the specific unsupported feature for `skip_reason`).
- Patterns needing a small, semantically-equivalent rewrite ⇒ `LOCAL_APPROXIMATE` (log a warning; must not change match semantics).
- **Never silently drop a rule** — every `CLOUD_ONLY` rule appears in the compatibility report with its reason.

⚠️ Open decision: the spec's sample SSN pattern uses negative lookaheads `(?!000|666|9\d{2})`. Strict RE2 rejects these → `CLOUD_ONLY`, unless we invest in a semantic range-rewrite to make them `LOCAL_APPROXIMATE`. Decide per the real rules file.

## Resource budget (the point of the PoC)

This runs on every endpoint, potentially in a file-access hot path. Validate every choice against the spec's budget:

- **≤ 50 MB** RAM peak.
- **≤ 3% CPU** on a representative egress event stream.
- **< 100 ms** end-to-end for files ≤ 500 KB (target p95); < 500 ms for 500 KB–5 MB.
- Stream / bound work; cap extracted text (default 5 MB); add a `Benchmark*` for anything on the hot path.

## Pipeline (spec §3)

```
file → 1. format detect (magic bytes)
     → 2. text extract (v0: plaintext/CSV · v1: OOXML via archive/zip · v2: PDF text layer)
     → 3. multi-pattern regex scan → dataset_id/rule_id matches
     → 4. post-match validators (luhn_check, checksum_iban, checksum_aba)
     → 5. label/marker detect (metadata fast-path → header/footer → body prefix/suffix)
     → 6. verdict builder (ALLOW / BLOCK / ESCALATE)
```

## Verdict logic (spec §4.6 defaults; configurable)

- **BLOCK** if any regex match with `validated_match_count ≥ 1` AND `confidence ≥ 0.85`.
- **BLOCK** if any label match from `metadata` source (machine-written, high confidence).
- **ESCALATE** if a relevant `CLOUD_ONLY` dataset applies, or content is encrypted/unreadable, or a regex match has `confidence < 0.85`.
- **ALLOW** if no matches and no applicable `CLOUD_ONLY` datasets.
- The PoC **reports** verdicts — it never enacts blocking.

## Intended layout (Go)

```
endpoint-ci/
├── cmd/ch-inspect/      # CLI: --rules <f> --file <f> | --report | --bench <dir>
├── internal/
│   ├── rules/           # load rules + RE2 compatibility classify + compat report
│   ├── format/          # magic-byte format detection
│   ├── extract/         # text extraction per file type
│   ├── scan/            # multi-pattern scan → matches (dataset_id/rule_id)
│   ├── validators/      # luhn, iban mod-97, aba
│   ├── label/           # label/marker detection (v1+)
│   └── verdict/         # ALLOW/BLOCK/ESCALATE builder + JSON output
├── testdata/corpus/     # synthetic samples (spec §7.1) — NO real PII
└── docs/                # design notes, consistency notes
```

## Conventions

- **Go style:** `gofmt`/`go vet` clean; small focused packages; prefer stdlib, justify every dependency (footprint matters).
- **Performance:** `Benchmark*` for hot-path code; avoid inner-loop allocations; stream don't read-all.
- **Thread safety (spec §10):** the rule database is read-only after load; inspection must not write shared state — per-call allocations.
- **Fail gracefully:** extraction/parse failure ⇒ `ESCALATE` with an error note, never panic/crash the caller. No network calls; only side effect is reading the input file.
- **No real data:** `testdata/` uses synthetic/fake sensitive data only.
- **British English** in docs and comments.

## Commands

```bash
go build ./...
go run ./cmd/ch-inspect --rules rules.json --file <path>   # scan a file
go run ./cmd/ch-inspect --rules rules.json --report        # compatibility report only
go run ./cmd/ch-inspect --rules rules.json --bench ./testdata/corpus   # latency p50/p95/p99
go test ./...
go test -bench=. -benchmem ./...
go vet ./... && gofmt -l .
```

## Deliverables (spec §9)

1. The library + CLI + tests (builds on macOS & Linux).
2. `compat_report.txt` — `--report` output against the real rules.
3. `benchmark_results.txt` — `--bench` latency stats over the corpus.
4. `consistency_notes.md` — any local-vs-expected-cloud divergences and why.

## Working with Claude

- Bias toward **runnable, measured increments**. Build the thin vertical slice (txt/csv: rules→scan→validate→verdict→bench), then OOXML, then PDF.
- The **real rules file is the gating input** for the compiler; until it lands, build against a synthetic file matching spec §5, swappable later.
- Keep `CURRENT_WORK.md` current; record significant choices in `DECISIONS.md`.
