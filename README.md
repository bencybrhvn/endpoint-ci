# endpoint-ci — local content inspection PoC

A self-contained, **offline** content-inspection engine that runs on the endpoint.
It loads a set of detection rules, extracts text from a file (plaintext, OOXML,
PDF), and returns a structured verdict — **ALLOW / BLOCK / ESCALATE** — built from
**detectors** (atomic data types like credit card, SSN, IBAN) composed into
**profiles** (PCI, US/UK/CA/EU PII, PHI/HIPAA, Secrets, Email, IP).

- 37 detectors · 10 profiles · all compile under Go's RE2 engine
- Document extraction: TXT/CSV, DOCX/XLSX/PPTX, PDF text layer
- Sensitivity-label fast-path (Microsoft MIP/AIP + custom markers)
- Within budget: ~p95 3 ms on real files, peak RSS < 20 MB

> **Architecture:** [`docs/architecture.md`](./docs/architecture.md) (diagrams). 
> **Contributing:** [`CONTRIBUTING.md`](./CONTRIBUTING.md).
> Background & design: [`overview.md`](./overview.md) (spec), [`CLAUDE.md`](./CLAUDE.md),
> [`DECISIONS.md`](./DECISIONS.md), [`docs/engine-notes.md`](./docs/engine-notes.md),
> [`docs/data-type-catalogue.md`](./docs/data-type-catalogue.md).

---

## Quick start

```bash
# 1. Get the code
git clone git@github.com:bencybrhvn/endpoint-ci.git
cd endpoint-ci

# 2. Build a binary (see "Building a binary" for static / cross-platform builds)
go build -o ch-inspect ./cmd/ch-inspect

# 3. Try it on a bundled sample (run from the repo root — see note below)
./ch-inspect --file testdata/corpus/pci_card.txt
```

Expected output (abridged):

```json
{
  "file": "testdata/corpus/pci_card.txt",
  "verdict": "BLOCK",
  "file_type": "plaintext",
  "scan_duration_us": 111,
  "profiles": [
    { "profile_id": "PCI", "data_type": "DT_Financial_PCI", "confidence": 80 },
    { "profile_id": "FINANCIAL", "confidence": 80 }
  ]
}
```

> **Run from the repo root.** The default rules file (`config/rules.json`) references
> lexicons by relative path (`config/lexicons/…`), so paths resolve when you run from
> the project root. To run elsewhere, pass `--rules /abs/path/to/config/rules.json`
> and keep `config/lexicons/` beside it.

### Prerequisites
- **Go 1.26+** (only needed to build; the resulting binary is standalone)
- macOS or Linux. The one dependency (`github.com/ledongthuc/pdf`) is pure Go — no cgo.

---

## Building a binary

```bash
# Native binary
go build -o ch-inspect ./cmd/ch-inspect

# Fully static binary (no libc dependency) — recommended for deployment
CGO_ENABLED=0 go build -o ch-inspect ./cmd/ch-inspect

# Cross-compile (examples)
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -o ch-inspect-linux-amd64 ./cmd/ch-inspect
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -o ch-inspect-linux-arm64 ./cmd/ch-inspect
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -o ch-inspect-darwin-arm64 ./cmd/ch-inspect
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o ch-inspect.exe         ./cmd/ch-inspect
```

The binary needs `config/rules.json` and `config/lexicons/` at runtime (pass
`--rules` to point at them). Everything else is compiled in.

---

## Usage

```bash
./ch-inspect --file <path>                 # inspect one file → verdict JSON
./ch-inspect --report                      # rule compatibility report (LOCAL_CAPABLE / CLOUD_ONLY)
./ch-inspect --bench testdata/corpus       # quick latency p50/p95/p99 over a flat dir
./ch-inspect --scan <dir>                  # recursively profile real files (see below)
```

### Profiling real files (`--scan`)

Recursively inspects every file under a directory and reports latency percentiles,
throughput, verdict + file-type breakdowns, the slowest files, and process memory.
Each file is inspected in an isolated child process (RSS cap + timeout) so a
malformed file can't take down the run.

```bash
./ch-inspect --scan ~/Documents --top 15 --csv results.csv
```

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--rules <path>` | `config/rules.json` | rules + profiles definition |
| `--file <path>` | | inspect a single file |
| `--report` | | print rule compatibility report and exit |
| `--bench <dir>` | | latency percentiles over a flat directory |
| `--scan <dir>` | | recursive real-world profiler |
| `--max-file-mb <n>` | 16 | size gate: larger files are head/tail inspected only |
| `--max-read-mb <n>` | 50 | `--scan`: skip files larger than this |
| `--top <n>` | 10 | `--scan`: show N slowest files |
| `--max-files <n>` | 0 (all) | `--scan`: cap files processed |
| `--csv <path>` | | `--scan`: write per-file results CSV |
| `--include-hidden` | false | `--scan`: include dot-dirs (e.g. `.git`) |
| `--isolate` | true | `--scan`: per-file child process (crash-safe) |
| `--rss-cap-mb <n>` | 512 | `--scan`: kill a child exceeding this RSS |
| `--file-timeout-sec <n>` | 8 | `--scan`: kill a child running longer than this |
| `--cpuprofile <path>` | | write a CPU pprof profile |
| `--memprofile <path>` | | write a heap pprof profile |

For pprof: `./ch-inspect --scan <dir> --cpuprofile cpu.out` then `go tool pprof cpu.out`.

---

## Worked examples

All three verdict types, run against bundled samples (`./ch-inspect --file …`).

**BLOCK** — `testdata/corpus/pci_card.txt` (two valid Luhn cards with payment context):

```jsonc
{
  "file": "testdata/corpus/pci_card.txt",
  "verdict": "BLOCK",
  "file_type": "plaintext",
  "short_circuited": true,                 // stopped once BLOCK was certain
  "scan_duration_us": 100,
  "profiles": [
    { "profile_id": "PCI",       "confidence": 80 },
    { "profile_id": "FINANCIAL", "confidence": 80 },
    { "profile_id": "US_PII",    "confidence": 80 }   // a card is also strong PII
  ],
  "detectors": [
    { "id": "credit_card", "raw_count": 2, "validated_count": 2, "confidence": 80 }  // Luhn-validated
  ]
}
```

**ESCALATE** — `testdata/corpus/ssn_nocontext.txt` (a valid SSN, but *no* nearby
keyword → uncertain, defer rather than block):

```jsonc
{
  "file": "testdata/corpus/ssn_nocontext.txt",
  "verdict": "ESCALATE",
  "file_type": "plaintext",
  "profiles":  [ { "profile_id": "US_PII", "confidence": 60 } ],  // 60 < block threshold 65
  "detectors": [ { "id": "us_ssn", "validated_count": 1, "confidence": 60 } ]
}
```

**ALLOW** — `testdata/corpus/clean.txt` (no sensitive data):

```jsonc
{
  "file": "testdata/corpus/clean.txt",
  "verdict": "ALLOW",
  "file_type": "plaintext",
  "profiles": null,
  "detectors": null
}
```

Office/PDF work the same way (text is extracted first), e.g.
`./ch-inspect --file testdata/docs/hipaa.docx` → BLOCK with `file_type: "docx"`.

### Profiling a directory (`--scan`)

```
$ ./ch-inspect --scan testdata/corpus --top 3
=== endpoint-ci real-world scan ===
files inspected: 18   (skipped >50MB: 0, killed OOM/timeout: 0)
isolation:       on (child per file, RSS cap 512MB, timeout 8s)
per-file latency:
  mean 102µs  p50 97µs  p90 137µs  p95 152µs  p99 152µs  max 157µs
verdicts:  ALLOW=3 (17%)  ESCALATE=3 (17%)  BLOCK=12 (67%)
memory impact:
  peak RSS:        ~18 MB
```

### Running the tests

```
$ go test ./...
ok   internal/engine       0.34s
ok   internal/validators   0.25s
...  (other packages have no tests)
```

## Validation against the Nucleuz policy test corpus

Beyond the bundled synthetic fixtures, the engine was profiled against Nucleuz's
own DLP **policy test data** (`…/NucleuzDlpEngine_DlpPoliciesRules_*/Test/
PoliciesTestData`) — a large set of real test files organised into `Matches/` and
`NonMatches/` per policy, which gives ground truth for both accuracy and timing.
That corpus is external/proprietary and **not** included in this repo; run it
yourself with `./ch-inspect --scan <PoliciesTestData> --csv results.csv`.

Results over **3,735 files / 529 MB**:

| Aspect | Result |
|---|---|
| Latency (per file) | p50 **754 µs** · p95 **3.2 ms** · p99 **18 ms** |
| Memory (parent) | peak RSS **~18 MB** |
| Verdicts | BLOCK 45% · ESCALATE 18% · ALLOW 37% |
| Match recall — implemented data types | **~100%** (Credit_Card, SSN, SWIFT, Canada_SIN, FR/ES/IT/CA/UK PII, IP…) |
| Match recall — overall | ~70% (the gap is ~22 policy types outside MVP scope: medical diagnoses, Australia TFN/IHI, AML, …) |
| Robustness | 24 malformed PDFs would OOM the parser (multi-GB) — contained by per-file process isolation; parent stayed at ~18 MB |

Two findings from this run drove design changes (standalone `EMAIL`/`IP_ADDRESS`
profiles; PDF process isolation in `--scan`). Full analysis, methodology, and the
NonMatches cross-detection caveat are in
[`docs/engine-notes.md`](./docs/engine-notes.md) (see "Real-world profiling").

## Verdicts

- **ALLOW** — no profile matched (a binary/unsupported type also ALLOWs — nothing to inspect).
- **ESCALATE** — a profile matched but below the block-confidence threshold, or coverage
  was incomplete (size gate / encrypted / unreadable). Defer to heavier/cloud inspection.
- **BLOCK** — a profile matched with high confidence. (The PoC *reports* — it never enforces.)

Each matched profile carries the contributing `data_type`, a `confidence`, and its
`verdict_on_match` ceiling (e.g. the `EMAIL` profile caps at ESCALATE).

---

## Testing

```bash
go test ./...                  # unit + corpus + document + validator tests
go test -race -count=1 ./...   # race detector, bypassing the test cache
go test -bench=. -benchmem ./internal/engine/   # latency/throughput benchmarks
```

Tests `chdir` to the repo root automatically, so they find `config/` and `testdata/`.
What's covered:
- `internal/engine` — corpus (`testdata/corpus` + `expectations.json`), document
  extraction (`testdata/docs`), early-exit, size gate.
- `internal/validators` — each checksum (Luhn, IBAN, ABA, VIN, SSN, EIN, NPI, DEA,
  ITIN, SIN, France NIR, Germany IdNr, Spain DNI, NL BSN) against known-valid values.
- `tools/validate-rules` — every pattern compiles under RE2; every profile resolves.

Validate the rules file directly:

```bash
go run ./tools/validate-rules config/rules.json
```

---

## Layout

```
cmd/ch-inspect/   CLI entrypoint (--file / --report / --bench / --scan)
internal/
  rules/          rule loading + RE2 compatibility classification
  format/         magic-byte format detection
  extract/        text extraction (plaintext, OOXML via zip, PDF text layer) + size gate
  prefilter/      Aho-Corasick multi-literal matcher (detector gating)
  label/          sensitivity-label detection (OOXML docProps + PDF XMP, + body)
  scan/           leaf detector scan (parallel, match-capped) + confidence model
  validators/     Luhn, IBAN, ABA, VIN, SSN, EIN, NPI, DEA, ITIN, SIN, NIR, …
  profile/        profile composition evaluator
  engine/         pipeline orchestration + verdict
tools/
  validate-rules/ compile-check patterns + resolve profile refs
  name-scan/       reference gazetteer name scorer
config/           rules.json + lexicons (name gazetteers)
testdata/corpus/  synthetic text samples (NO real PII)
testdata/docs/    synthetic DOCX/XLSX/PPTX/PDF fixtures
docs/             design & engine notes
deliverables/     compat_report.txt, benchmark_results.txt
```

Sole third-party dependency: `github.com/ledongthuc/pdf` (pure-Go PDF text). OOXML
uses the standard library only.

---

## Editing the rules

`config/rules.json` defines `detectors` (regex/dictionary leaf types with validators
and prefilter cues) and `profiles` (boolean compositions with a `verdict_on_match`
ceiling). After any edit, run `go run ./tools/validate-rules config/rules.json` to
confirm every pattern is RE2-compatible and every profile reference resolves.

## Browser / WASM demo

The engine compiles to WebAssembly and runs in a browser — files are inspected
entirely in the page, nothing is uploaded. This is the basis for a browser-extension
deployment.

```bash
./web/build.sh                          # compile ch.wasm + stage runtime/rules
cd web && python3 -m http.server 8080   # open http://localhost:8080/
```

Drop a file (txt/csv/docx/xlsx/pptx/pdf) or paste text → verdict + profiles + scan
time, computed locally by the same Go engine (~1.5 MB gzipped WASM). The engine runs
in a **Web Worker** that the page terminates on timeout, so a malicious file (e.g. a
memory-bomb PDF) is isolated rather than hanging the tab. Verified across the full
Nucleuz corpus incl. PDFs (24 bomb PDFs isolated; 99.7% verdict parity with native).
See [`web/README.md`](./web/README.md).

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for setup, conventions, and step-by-step
recipes (add a detector, profile, validator, label marker, or file format) and
[`docs/architecture.md`](./docs/architecture.md) for the pipeline and package map.

## Status

PoC complete across: rule model, validators, OOXML + PDF extraction, sensitivity
labels, the latency/memory budget, multi-pattern matcher + parallel scan + early-exit,
size gate, and a real-world profiler. Open items are tracked in `CURRENT_WORK.md`
(sensor integration, sandboxed extraction in production, more locales).
