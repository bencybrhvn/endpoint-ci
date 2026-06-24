# Contributing

Thanks for working on `endpoint-ci`. This is a PoC for a fast, offline,
on-endpoint content-inspection engine. Keep changes small, measured, and tested.

> Read [`docs/architecture.md`](./docs/architecture.md) first for the pipeline and
> package map, and [`CLAUDE.md`](./CLAUDE.md) / [`DECISIONS.md`](./DECISIONS.md) for
> context and the rationale behind key choices.

## Setup

```bash
git clone git@github.com:bencybrhvn/endpoint-ci.git
cd endpoint-ci
go build ./...
go test ./...
```

Requires **Go 1.26+**. Run commands from the repo root (rules/lexicons resolve by
relative path).

## Before you push

```bash
gofmt -w .                       # format
go vet ./...                     # static checks
go test -race -count=1 ./...     # tests + race detector, no cache
go run ./tools/validate-rules config/rules.json   # if you touched rules.json
```

All four must be clean. Match the style of the surrounding code; keep packages
small and focused; prefer the standard library and justify any new dependency
(binary footprint matters on the endpoint).

## Conventions

- **British English** in docs/comments.
- **RE2 only**: patterns must compile under Go's `regexp` (no lookahead/lookbehind/
  backreference). Move value-validity logic into a validator instead (see SSN).
- **Fail gracefully**: extraction/parse errors degrade to a verdict (usually
  ESCALATE), never panic the caller.
- **No real data**: `testdata/` is synthetic only. Validators are tested against
  well-known public test values, not real identifiers.
- Record notable design choices in `DECISIONS.md`; keep `CURRENT_WORK.md` (local,
  git-ignored) updated as you go.

---

## How to add a detector (leaf data type)

1. **Pattern** — add to `config/rules.json → detectors` (RE2-safe). Use
   `prefilter.needs_digit` and/or `prefilter.literals` so it can be skipped cheaply.
   Make high-false-positive shapes `best_effort: true` (keyword-gated).
2. **Validator (optional)** — if there's a checksum, add it to
   `internal/validators/validators.go`, register it in the `registry` map, and add a
   known-valid/known-invalid case to `validators_test.go`.
3. **Wire into a profile** — reference the detector id under the relevant profile's
   `match` tree (`min_validated: 1` if it has a validator).
4. **Validate** — `go run ./tools/validate-rules config/rules.json`.
5. **Test** — add a `testdata/corpus/<case>.txt` with synthetic data and an entry in
   `testdata/corpus/expectations.json`, then `go test -count=1 ./...`.

## How to add a profile (named concept)

1. Add to `config/rules.json → profiles` with a `match` tree of `op`s:
   `detector` (`id`, optional `min_validated`/`min_count`), `or` (`min`, `of[]`),
   `and` (`of[]`).
2. Set `verdict_on_match` as the **severity ceiling** (`BLOCK` or `ESCALATE`).
3. Validate + add a corpus case as above.

## How to add a sensitivity-label marker

Add to `config/rules.json → label_markers`: `strings` (visible label values) and
`metadata_properties` (document-property names, e.g. `MSIP_Label`). The metadata
fast-path matches both for OOXML docProps and PDF XMP; distinctive body markings
(multi-word / all-caps) are matched in extracted text.

## How to support a new file format

Add a type to `internal/format` (magic-byte detection) and an extraction branch in
`internal/extract`. Keep extraction bounded and recover from library panics.

## Project map (quick)

| You want to… | Edit |
|---|---|
| add/adjust a data type or profile | `config/rules.json` |
| add a checksum | `internal/validators` |
| change scan/confidence behaviour | `internal/scan` |
| change verdict/early-exit logic | `internal/engine` |
| add a file format / extraction | `internal/format`, `internal/extract` |
| add a sensitivity-label source | `internal/label`, `config/rules.json` |
| add a CLI flag / profiler feature | `cmd/ch-inspect` |

## Regenerating deliverables

```bash
go run ./cmd/ch-inspect --report > deliverables/compat_report.txt
go run ./cmd/ch-inspect --bench testdata/corpus  # numbers for benchmark_results.txt
```

## Pull requests

- One logical change per PR; explain the *why* in the description.
- Include test coverage for new behaviour.
- Note any measured performance/footprint impact for hot-path changes.
- End commit messages with the project's `Co-Authored-By` trailer if applicable.
