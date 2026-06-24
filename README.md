# endpoint-ci — `ch_local_inspect`

A self-contained, **offline** content inspection PoC that runs on the endpoint. It ingests Cyberhaven's **existing cloud-side content inspection rules** (datasets), compiles them into a local pattern database, and returns a structured verdict — **ALLOW / BLOCK / ESCALATE** — using the **same `dataset_id`s as the cloud**, so local and remote verdicts on the same file are directly comparable.

> Full specification: [`overview.md`](./overview.md). Project context & decisions: [`CLAUDE.md`](./CLAUDE.md), [`DECISIONS.md`](./DECISIONS.md).

## Core idea: one rule source

Cloud and local inspection **share the same rules**. The rules file is read-only input; `dataset_id`/`rule_id` pass through unmodified into verdicts (`scan_path: "local"`), so drift between local and cloud verdicts on identical content is detectable.

## Implementation note

Built in **Go** (not the spec's C). Go's standard-library `regexp` *is* an RE2 implementation, so the spec's RE2-compatibility classifier (`LOCAL_CAPABLE` / `LOCAL_APPROXIMATE` / `CLOUD_ONLY`) is native — no cgo. OOXML extraction uses `archive/zip` + `encoding/xml`. See `DECISIONS.md`.

## Resource budget (PoC success criteria)

- ≤ 50 MB RAM peak · ≤ 3% CPU on a representative event stream
- < 100 ms end-to-end for files ≤ 500 KB (target p95)

## Status

Early PoC. Building **v0** (plaintext/CSV end-to-end), then OOXML, then PDF. See `CURRENT_WORK.md`.

## Getting Started

### Prerequisites
- Go 1.26+

### Build & Run
```bash
go build ./...
go run ./cmd/ch-inspect --rules rules.json --file <path>           # scan a file
go run ./cmd/ch-inspect --rules rules.json --report               # rule compatibility report
go run ./cmd/ch-inspect --rules rules.json --bench ./testdata/corpus   # latency p50/p95/p99
```

### Test & Benchmark
```bash
go test ./...
go test -bench=. -benchmem ./...
```

## Layout

```
cmd/ch-inspect/   CLI entrypoint (--file / --report / --bench)
internal/
  rules/          rule loading + RE2 compatibility classification
  format/         magic-byte format detection
  extract/        text extraction (plaintext, OOXML via zip, PDF text layer)
  prefilter/      Aho-Corasick multi-literal matcher (detector gating)
  label/          OOXML sensitivity-label detection (metadata fast-path + body)
  scan/           leaf detector scan (parallel, match-capped) + confidence model
  validators/     luhn, iban (mod-97), aba, vin, ssn, ein, npi, dea
  profile/        profile composition evaluator
  engine/         pipeline orchestration + verdict
testdata/corpus/  synthetic text samples (NO real PII)
testdata/docs/    synthetic DOCX/XLSX/PPTX/PDF fixtures
config/           rules.json + lexicons
docs/             design & engine notes
```

Sole third-party dependency: `github.com/ledongthuc/pdf` (pure-Go PDF text). OOXML uses the standard library only.

## Deliverables

`compat_report.txt`, `benchmark_results.txt`, `consistency_notes.md` — see `overview.md` §9.
