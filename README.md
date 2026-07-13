# endpoint-ci — local content inspection PoC

A self-contained, **offline** content-inspection engine that runs on the endpoint.
It loads a set of detection rules, extracts text from a file (plaintext, OOXML,
PDF), and returns a structured **match report** — *what* sensitive content it found,
with confidence — built from **detectors** (atomic data types like credit card, SSN,
IBAN, source code) composed into **profiles** (PCI, US/UK/CA/EU PII, PHI/HIPAA,
Secrets, Source Code, Email, IP). It **inspects and reports only**: the block/allow
decision belongs to a separate policy engine that consumes the report (see
[`DECISIONS.md`](./DECISIONS.md) 2026-07-07).

- 38 detectors · 11 profiles · all compile under Go's RE2 engine
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
  "file_type": "plaintext",
  "readable": true,
  "coverage": "full",
  "scan_duration_us": 111,
  "profiles": [
    { "profile_id": "PCI", "data_type": "DT_Financial_PCI", "confidence": 80 },
    { "profile_id": "FINANCIAL", "data_type": "DT_Financial_PCI", "confidence": 80 }
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
./ch-inspect --file <path>                 # inspect one file → match report JSON
./ch-inspect --report                      # rule compatibility report (LOCAL_CAPABLE / CLOUD_ONLY)
./ch-inspect --bench testdata/corpus       # quick latency p50/p95/p99 over a flat dir
./ch-inspect --scan <dir>                  # recursively profile real files (see below)
```

### Profiling real files (`--scan`)

Recursively inspects every file under a directory and reports latency percentiles,
throughput, match + file-type breakdowns, the slowest files, and process memory.
Each file is inspected in an isolated child process (RSS cap + timeout) so a
malformed file can't take down the run.

```bash
./ch-inspect --scan ~/Documents --top 15 --csv results.csv
```

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--rules <path>` | `config/rules.json` | rules + profiles definition |
| `--file <path>` | | inspect a single file → match report |
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

Four reports, run against bundled samples (`./ch-inspect --file …`). The engine
reports *what it found* and *how strong the match is* — it never emits an action.
A match at or above `high_confidence_threshold` (65) is flagged high-confidence; a
weaker match is still reported for the policy layer to weigh. Output is trimmed.

**Strong match** — `testdata/corpus/pci_card.txt` (two valid Luhn cards with payment
context). Confidence 80 (≥ 65 → high-confidence); `short_circuited` because the
strong signal let the scan stop early:

```jsonc
{
  "file": "testdata/corpus/pci_card.txt",
  "file_type": "plaintext",
  "readable": true,
  "coverage": "full",
  "short_circuited": true,
  "note": "short-circuited: strong signal found, remaining detectors skipped",
  "scan_duration_us": 501,
  "profiles": [
    { "profile_id": "PCI",       "data_type": "DT_Financial_PCI",     "confidence": 80, "rules": ["credit_card"] },
    { "profile_id": "FINANCIAL", "data_type": "DT_Financial_PCI",     "confidence": 80, "rules": ["credit_card"] },
    { "profile_id": "US_PII",    "data_type": "DT_PII_Personal_Data", "confidence": 80, "rules": ["credit_card"] }
  ],
  "detectors": [
    { "id": "credit_card", "data_types": ["DT_Financial_PCI", "DT_PII_Personal_Data"],
      "raw_count": 2, "validated_count": 2, "confidence": 80 }   // Luhn-validated
  ]
}
```

**Low-confidence match** — `testdata/corpus/ssn_nocontext.txt` (a valid SSN, but
*no* nearby keyword). It still matches, but at confidence 60 — below the
high-confidence threshold, a signal the policy layer can treat cautiously:

```jsonc
{
  "file": "testdata/corpus/ssn_nocontext.txt",
  "file_type": "plaintext",
  "readable": true,
  "coverage": "full",
  "profiles":  [ { "profile_id": "US_PII", "data_type": "DT_PII_Personal_Data",
                   "confidence": 60, "rules": ["us_ssn"] } ],   // 60 < high_confidence_threshold 65
  "detectors": [ { "id": "us_ssn", "data_types": ["DT_PII_Personal_Data"],
                   "raw_count": 1, "validated_count": 1, "confidence": 60 } ]
}
```

**No match** — `testdata/corpus/clean.txt` (no sensitive data). Reported as a clean,
fully-readable scan:

```jsonc
{
  "file": "testdata/corpus/clean.txt",
  "file_type": "plaintext",
  "readable": true,
  "coverage": "full",
  "profiles": null,
  "detectors": null
}
```

**Source code** — `testdata/corpus/code_go.txt` (the new `source_code` detector →
`SOURCE_CODE` profile; see [Source-code detection](#source-code-detection) below):

```jsonc
{
  "file": "testdata/corpus/code_go.txt",
  "file_type": "plaintext",
  "readable": true,
  "coverage": "full",
  "short_circuited": true,
  "scan_duration_us": 196,
  "profiles": [
    { "profile_id": "SOURCE_CODE", "profile_name": "Source Code",
      "data_type": "DT_Source_Code", "confidence": 86, "rules": ["source_code"] }
  ],
  "detectors": [
    { "id": "source_code", "data_types": ["DT_Source_Code"],
      "raw_count": 12, "validated_count": 12, "confidence": 86 }
  ]
}
```

Office/PDF work the same way (text is extracted first), e.g.
`./ch-inspect --file testdata/docs/hipaa.docx` → PHI_HIPAA/US_PII with
`file_type: "docx"`.

### Source-code detection

`source_code` (detector kind `code`) and the `SOURCE_CODE` profile
(`data_type: DT_Source_Code`) detect program source in any language. Source code
has no checksum, so — like the person-name dictionary detector — this is a
**language-agnostic scoring classifier**, not regex + validator. Confidence comes
from combining evidence families (keyword and operator density, structural
punctuation, indentation, comment markers) and **penalising natural-language
prose**, behind a **minimum-keyword gate** that keeps JSON/YAML/prose/logs from
firing. Weights and token sets live in `config/rules.json` under the detector's
`code` block (tunable without recompiling); feature extraction is `scanCode` in
`internal/scan/scan.go`.

Validated on a small corpus:

| Class | Files | Result |
|---|---|---|
| Source code | Python, Go, JavaScript, Java, C | all fire, **86–95** confidence |
| Confusables | JSON, YAML, Markdown prose, logs | all correctly **silent** |

Cost stays well within budget: a 500 KB source file inspects in **~20 ms** with
**43 allocations**.

A companion **Secrets** capability (`api_key` / `private_key` / `jwt` → `SECRETS`
profile) already existed and is unrelated to source-code *classification* — it
catches embedded credentials rather than code itself.

### Profiling a directory (`--scan`)

```
$ ./ch-inspect --scan testdata/corpus --top 3
=== endpoint-ci real-world scan ===
files inspected: 27   (skipped >50MB: 0, killed OOM/timeout: 0)
isolation:       on (child per file, RSS cap 512MB, timeout 8s)
per-file latency:
  mean 141µs  p50 129µs  p90 186µs  p95 238µs  p99 259µs  max 317µs
matches:   clean=8 (30%)  matched=19 (70%)  of-which-high-confidence=17  unreadable=0
short-circuited: 17   partial (size gate): 0
memory impact:
  peak RSS:        ~11.5 MB
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

Measured results over **3,735 files / 528.7 MB** (release `4.55.14007.14035`):

| Aspect | Result |
|---|---|
| Latency (per file) | p50 **721 µs** · p90 **2.1 ms** · p95 **3.0 ms** · p99 **19.8 ms** |
| Memory (parent) | peak RSS **~17 MB** |
| Matches | matched **2,227 (60%)** · clean **1,508 (40%**, incl. 189 unreadable/encrypted**)** · of matched, **1,834** high-confidence |
| Match recall — implemented data types | **~100%** (Credit_Card, SSN, SWIFT, Canada_SIN, FR/ES/IT/CA/UK PII, IP…) |
| Robustness | 24 malformed PDFs would OOM the parser (multi-GB) — contained by per-file process isolation; parent stayed at ~17 MB |

Two findings from earlier runs drove design changes (standalone `EMAIL`/`IP_ADDRESS`
profiles; PDF process isolation in `--scan`). Full analysis, methodology, and the
NonMatches cross-detection caveat are in
[`docs/engine-notes.md`](./docs/engine-notes.md) (see "Real-world profiling").

### Source-code detection — ground-truth validation

The corpus includes an `Intellectual_Property/Matches/` folder of real source-code
samples across 14 languages, which is independent ground truth for the new
`source_code` classifier (it was calibrated on a *separate* synthetic set, so this
is a genuine held-out test):

| Aspect | Result |
|---|---|
| Recall (real source files) | **10 / 14** — Go, Java, JavaScript, C#, C++, C(+header), Perl, PHP, Fortran, SQL fire at 75–95 confidence |
| Recall misses | a 2-line Bash stub (below `min_lines`), and three licence-/data-dominated files (large C, an 81 KB data-heavy Python, a string-demo Ruby) |
| Precision | **0 false positives across all 2,278 non-PDF files** — including legal/government prose (`US_CUI`, a notarial-law doc with 100+ "public" hits) and long articles (Māori-language `.docx`) |

Calibrating against this real corpus surfaced two things a synthetic set never would,
now fixed in `scanCode`: (1) real source opens with big **English licence/doc-comment
blocks** — comment lines must count as code, not prose; (2) `.docx`/`.pdf` extraction
**concatenates paragraphs into a few long lines**, so keyword density is normalised by
an *estimated logical-line count* rather than raw lines, and prose is detected by
**symbol density** (not a terminal full stop, which extraction strips). Detection is
notably robust: Perl, C#, Fortran and SQL were **not** in the calibration set yet all fire.

## What the report says

This engine **inspects and reports — it does not decide actions.** There is no
ALLOW/BLOCK/ESCALATE. Whether a report warrants blocking, quarantine or nothing is
a **policy decision made by a separate component** that consumes the report. This is
a deliberate design: a content inspector shouldn't own the enforcement decision or
speak in enforcement vocabulary (see [`DECISIONS.md`](./DECISIONS.md) 2026-07-07).

A `Report` carries:

- **`profiles[]`** — the matched named concepts (PCI, US_PII, SOURCE_CODE…), each
  with its `data_type`, a `confidence` (0–100), and the contributing leaf `rules`
  (rule_ids) as evidence. A profile is just a concept — there is **no**
  `verdict_on_match`.
- **`detectors[]`** — every fired leaf detector, with `data_types` (the `dataset_id`s,
  passed through unmodified for cloud comparability), `raw_count`, `validated_count`
  and `confidence`.
- **`labels[]`** — sensitivity labels with their `source` (`metadata` = machine-written,
  authoritative; `body` = distinctive marking).
- **Neutral scan facts** the policy layer weighs — these are observations, *not*
  actions:
  - `readable` — `false` when the file was encrypted, corrupt or binary, so no body
    was inspected (a `note` records unsupported-vs-encrypted).
  - `coverage` — `full`, `partial` (size gate: only head/tail inspected) or
    `truncated`.
  - `short_circuited` — the scan stopped early on a strong signal, so the profile
    list may be partial.

`confidence` and the `high_confidence_threshold` (65) are a **detection-quality**
signal — how strong is this match — kept deliberately separate from any action. The
old ESCALATE states are now reported as facts: encrypted/unreadable → `readable:false`;
incomplete coverage → `coverage:"partial"`; a low-confidence match is simply reported
below the threshold. The policy layer decides what to do with each.

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
  engine/         pipeline orchestration + match Report
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

`config/rules.json` defines `detectors` (leaf data types — kind `regex` /
`dictionary` / `code`, with validators and prefilter cues) and `profiles` (boolean
compositions over detectors → a named concept + `data_type`; profiles carry **no**
`verdict_on_match` — the engine reports, it doesn't decide actions). The `code`
detector kind is the language-agnostic source-code classifier, whose weights and
token sets live in its `code` block. After any edit, run
`go run ./tools/validate-rules config/rules.json` to confirm every pattern is
RE2-compatible and every profile reference resolves.

## Browser / WASM demo

The engine compiles to WebAssembly and runs in a browser — files are inspected
entirely in the page, nothing is uploaded. This is the basis for a browser-extension
deployment.

```bash
./web/build.sh                          # compile ch.wasm + stage runtime/rules
cd web && python3 -m http.server 8080   # open http://localhost:8080/
```

Drop a file (txt/csv/docx/xlsx/pptx/pdf) or paste text → matched profiles +
confidence + scan time, computed locally by the same Go engine (~1.5 MB gzipped
WASM). The badge shows NO MATCH / MATCH / UNREADABLE / ISOLATED. The engine runs in a
**Web Worker** that the page terminates on timeout, so a malicious file (e.g. a
memory-bomb PDF) is isolated rather than hanging the tab. Verified across the full
Nucleuz corpus incl. PDFs (24 bomb PDFs isolated; 99.7% report parity with native).
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
