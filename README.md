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
cmd/ch-inspect/   CLI entrypoint
internal/
  rules/          rule loading + RE2 compatibility classification + report
  format/         magic-byte format detection
  extract/        text extraction per file type
  scan/           multi-pattern regex scan → dataset_id/rule_id matches
  validators/     luhn, iban (mod-97), aba
  label/          label / sensitivity-marker detection
  verdict/        ALLOW/BLOCK/ESCALATE builder + JSON output
testdata/corpus/  synthetic sample files (NO real PII)
docs/             design & consistency notes
```

## Deliverables

`compat_report.txt`, `benchmark_results.txt`, `consistency_notes.md` — see `overview.md` §9.
