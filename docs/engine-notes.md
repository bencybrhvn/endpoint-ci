# Engine notes & findings (PoC)

The local inspection engine, run against the synthetic corpus. The engine
**inspects and reports only** — it emits a match report, never an action. Blocking /
allowing is a *policy* decision made by a separate component that consumes the report
(see [`../DECISIONS.md`](../DECISIONS.md) 2026-07-07). There is no
ALLOW/BLOCK/ESCALATE.

## Pipeline

```
file → detect format (magic bytes)
     → extract text (plaintext direct · OOXML via archive/zip · PDF text layer)
     → prefilter (Aho-Corasick literals + needs-digit, one pass → skip detectors)
     → scan (leaf detectors: regex + dictionary + code, run across cores, match-capped)
       in priority-ordered batches; re-evaluate profiles after each batch and
       short-circuit once a high-confidence match is found
     → confidence model (base +validator +keyword +instances)
     → profile evaluation (and/or/min/min_validated over fired detectors)
     → Report: matched profiles + confidence + evidence, plus neutral scan facts
       (readable, coverage, short_circuited)
```

## Extraction layer

- **Format detection** (`internal/format`) — magic bytes: `%PDF` → PDF; `PK\x03\x04`
  → inspect ZIP entries for DOCX/XLSX/PPTX; `D0CF11E0` (OLE) → encrypted/legacy;
  valid UTF-8 with no NULs → plaintext.
- **Extraction** (`internal/extract`):
  - *OOXML* — `archive/zip` over the text-bearing parts (`word/document.xml`,
    headers/footers, `xl/sharedStrings.xml`, `ppt/slides/*`, doc properties) +
    a tag-stripping pass. Stdlib only.
  - *PDF* — text layer via `ledongthuc/pdf` (pure Go), wrapped in a recover.
  - Encrypted/legacy/unsupported/parse failure → reported as `readable: false` with a
    note; never crashes the caller (spec §10 fail-gracefully).
- Extracted text is capped (default 5 MB) and flagged `coverage: "truncated"`.

### Size gate + head/tail extraction (spec §4.3)

Files above the **size gate** (`MaxFileBytes`, default 16 MB; CLI `--max-file-mb`)
are reduced to their **head + tail windows** (`HeadTailWindow`, default 64 KB each)
— the middle is not inspected, so cost is bounded regardless of file size. For
plaintext the gate is applied on the raw bytes (we never build a huge string).
The result is flagged `Partial`.

**Coverage-aware report:** partial (or truncated) extraction means a clean
result is only "clean for what we saw", so the report says `coverage: "partial"`
rather than silently implying the whole file is clean — the unseen middle isn't
passed off as inspected. Any profile/label that *does* fire in the head/tail is
reported as normal. (Demo: a 21 MB clean file with a 1 MB gate → 131 KB inspected,
`coverage: "partial"`, ~18 ms.) The policy layer decides whether partial coverage
warrants heavier/cloud inspection. The metadata label fast-path always runs on the
full container (docProps are tiny), so labels are caught even under the gate.

### Sensitivity-label fast-path (spec §4.5)

`internal/label` detects classification labels:
- **Metadata fast-path** — reads *only* the container's property metadata (no body
  extraction):
  - *OOXML* — `docProps/custom.xml` + `core.xml` from the zip.
  - *PDF* — the **XMP packet** (`<?xpacket…?>`) located in the raw bytes; property
    names matched with separator/case-insensitive normalisation so `msip:Label`
    matches the `MSIP_Label` cue. (Compressed XMP streams aren't handled — noted.)
  Property names match marker `metadata_properties` (`MSIP_Label`, `Sensitivity`,
  `Classification`, `DataClass`…) and values match marker `strings`. A metadata
  label is machine-written → authoritative; it is reported in `labels[]` with
  `source: "metadata"`. The fast-path runs **even when text extraction fails**, so a
  labelled-but-unparseable document is still reported (label + `readable: false`)
  rather than lost.
- **Body fallback** — scans already-extracted text for *distinctive* markings
  (multi-word or all-caps, case-sensitive: `COMPANY CONFIDENTIAL`, `TOP SECRET`,
  `INTERNAL USE ONLY`…) so the bare word "Confidential" in prose doesn't trip it.
  A body marking is reported with `source: "body"`.

Markers come from the `label_markers` section of `config/rules.json`. Labels appear
in the report's `labels[]` with their `source` (`metadata`/`body`); the engine no
longer upgrades anything on their account — the policy layer weighs `source`.
Verified: `labeled.docx` (OOXML MSIP property) and `labeled.pdf` (PDF XMP MSIP
label) report a `metadata` label; `footer_marked.docx` reports a `body` label.

Verified end to end (`go test`): `hipaa.docx`→PHI/PII, `pci.xlsx`→PCI/Financial,
`financial.pptx`→Financial, `pii.pdf`→US_PII, `clean.docx`→no match,
`legacy.doc` (OLE)→`readable: false`.

Packages: `internal/rules` (load + RE2 compat classify + per-detector pattern
combine), `internal/validators` (luhn/iban/aba/vin/ssn/ein/npi/dea),
`internal/scan` (detectors + confidence), `internal/profile` (composition),
`internal/engine` (orchestration + Report). CLI: `cmd/ch-inspect`.

## Report model (supersedes the old verdict logic; see DECISIONS.md 2026-07-07)

The engine reports what it found; it does not decide an action. There is no
ALLOW/BLOCK/ESCALATE.

- A profile that matches is reported with its `data_type`, `confidence`, and
  contributing leaf `rules`. A match at ≥ `high_confidence_threshold` (65) is
  flagged high-confidence (e.g. a valid SSN *with* a surrounding context keyword);
  a weaker match (e.g. the same SSN with no context) is reported below the threshold
  for the policy layer to weigh cautiously.
- No profile matched → the report simply has no `profiles` (detector findings may
  still be reported).
- Old ESCALATE states are now neutral facts: encrypted/unreadable → `readable: false`;
  incomplete coverage → `coverage: "partial" | "truncated"`.

`confidence` + the `high_confidence_threshold` are a **detection-quality** signal,
kept distinct from the action (which policy owns). The threshold also drives the
hot-path early-exit (`stop_on_high_confidence`).

## Corpus results (10/10 as expected — `go test ./...`)

| File | Match | Profiles |
|---|---|---|
| pci_card.txt | high-confidence | PCI, FINANCIAL, US_PII |
| financial_iban.txt | high-confidence | FINANCIAL |
| ssn_context.txt | high-confidence | US_PII |
| ssn_nocontext.txt | **low-confidence** | US_PII (60 < 65) |
| pii_multi.txt | high-confidence | US_PII (email + phone) |
| hipaa.txt | high-confidence | US_PII, PHI_HIPAA |
| secrets.txt | high-confidence | SECRETS |
| card_invalid_luhn.txt | no match | — (Luhn rejected the FP) |
| names_only.txt | no match | — (one detector ≠ ≥2 distinct PII) |
| clean.txt | no match | — |

These confirm the design intent: validators kill FPs (invalid Luhn → no match),
context drives high- vs low-confidence (SSN with/without keyword), and a lone weak
signal (names only) cannot raise a profile.

## Source-code classifier (`source_code` → SOURCE_CODE)

Source code is a data type with **no checksum**, so — unlike the regex+validator
detectors — `source_code` (detector kind `code`) is a **language-agnostic scoring
classifier**, in the same spirit as the person-name dictionary detector. Rather than
one pattern, it combines several **evidence families** and scores them:

- keyword / operator density (against language-agnostic token sets),
- structural punctuation (`{ } ( ) ; =` …),
- indentation regularity,
- comment markers,
- a **penalty for natural-language prose**,

behind a **minimum-keyword gate**: below a floor of code keywords the detector stays
silent, which is what keeps JSON, YAML, Markdown prose and log files from firing.
Weights and token sets live in `config/rules.json` under the detector's `code` block,
so the classifier is tunable without recompiling; feature extraction is `scanCode` in
`internal/scan/scan.go`.

Validated against the Nucleuz corpus's own held-out source-code ground truth
(`Intellectual_Property/Matches/`, 14 languages): **10/14** fire at **75–95**
confidence — including Perl, C#, Fortran and SQL, which were *not* in the calibration
set — with **0 false positives across all 2,278 non-PDF files**. Two failure modes the
synthetic set hid drove the final design (see DECISIONS.md 2026-07-08): comment/licence
blocks count as code not prose, and — because document extraction concatenates
paragraphs into a few long lines — keyword density is normalised by an estimated
logical-line count (`max(lines, words/12)`) with prose detected by symbol density.
Cost is within budget — a 500 KB source file inspects in **~20 ms** with **43
allocations**.

**Future optimisation:** the code-keyword counting overlaps with the Aho-Corasick
literal prefilter. Folding the code keyword set into the prefilter automaton would let
a single existing pass tell us whether *any* code keyword is present, so the scorer
(and its feature extraction) can be skipped entirely on text with no code keywords —
the same "skip the expensive step when the cheap cue is absent" trick the prefilter
already applies to literal-anchored regex detectors.

## Performance — multi-pattern matcher (within budget)

Throughput ≈ **17 MB/s** (was 2.8 MB/s before optimisation):

| Input | Latency | Budget (<100 ms ≤500 KB) |
|---|---|---|
| Typical ≤ 8 KB | ~0.7 ms | ✅ |
| 500 KB, PII-dense | ~31 ms | ✅ |
| 500 KB, mostly prose + trailing PII | ~33 ms | ✅ |

### Techniques (all preserve independent-detector semantics)
1. **Aho-Corasick literal prefilter** (`internal/prefilter`) — one pass over the
   buffer reports which literal cues are present (`AKIA`, `eyJ`, `@`, `http`, …);
   a literal-anchored detector whose cue is absent is skipped entirely. Plus a
   one-shot `needs_digit` check. This is the multi-pattern matcher front end.
2. **Best-effort keyword gating** — context-gated detectors skip their regex if
   their keyword is absent anywhere (DOB 40 ms → 0.4 ms on text with no DOB).
3. **Per-detector pattern combine** — a detector's patterns are OR'd into one regex.
4. **Match cap (64)** — `FindAllStringIndex(text, 64)` stops scanning once enough
   matches are found; we never need all 2008 cards to know a file is PCI. Far above
   any profile threshold, so reported matches are unchanged.
5. **Parallel detector scan** — detectors are read-only and independent, so they
   run across `NumCPU` goroutines. Per-file latency drops ~Ncore×; CPU is a brief
   burst, not steady-state (the ≤3% CPU budget is amortised over an event stream).
   Race-clean (`go test -race`).
6. **Early-exit short-circuit** — detectors run in priority-ordered batches
   (validator-backed/strong first). After each batch we re-evaluate profiles; once
   a high-confidence match is found (`stop_on_high_confidence`, or matches saturate
   `max_total_matches`), we stop — remaining detectors can only *add* to an
   already-strong report. On saturated input this skips most detectors (allocs
   dropped ~65×). **Trade-off:** a short-circuited report is flagged
   `short_circuited` and may list a *partial* set of profiles (we stopped once the
   match was clearly strong). Detection-completeness tests run with early-exit
   disabled; the fast path is covered by `TestEarlyExit`.

### What we tried and rejected
- **Single mega-regex (all detectors in one alternation)** — *reverted*. In one
  alternation, overlapping detectors **steal** each other's matches (the generic
  `\d{9}` ABA detector consumed an NPI's digits, so HIPAA stopped firing), and the
  large submatch arrays made it slower. RE2 set-matching reports *which* patterns
  match, not all per-pattern positions, so it can't replace independent scans.

### Caveats / further headroom (post-PoC)
- The match cap means counts saturate at 64 (fine for our thresholds; revisit if a
  profile ever needs `min_count` > 64).
- A genuinely pathological buffer (one 500 KB token matching many detectors) would
  still cost N scans; a true vectorised matcher (Hyperscan) is the production path.
- Size gate + head/tail extraction for very large files (spec `ExtractConfig`).

## Real-world profiling (`--scan`) + robustness findings

`ch-inspect --scan <dir>` recursively profiles real files: latency percentiles,
throughput, match + file-type breakdowns, slowest files, heap + peak RSS, optional
`--cpuprofile`/`--memprofile`/`--csv`. Dot-dirs are skipped by default.

Run against a labelled policy test corpus (**3,735 files / 529 MB**):
- **Latency** p50 758µs, p95 3.3ms, p99 18ms — well within budget (the headline
  mean/max are skewed by isolated-timeout files, below).
- **Parent peak RSS 17.5 MB.**
- **Accuracy** (vs `Matches`/`NonMatches` ground truth): ~100% recall on the data
  types we implement (Credit_Card, Canada_SIN, SWIFT, FR/ES/IT/CA PII…); overall
  recall is lower only because the corpus spans ~all policies incl. ~22 types we
  don't implement (medical diagnoses, Australia TFN/IHI, AML…).

### Finding 1 — single-signal types weren't reported (now addressed)
`IP_Address`-only / email-only files originally matched no *profile*: the detector
fired but no profile was satisfied by one weak signal, so the report was empty.
**Resolved** by adding standalone `EMAIL` and `IP_ADDRESS` profiles so a lone
email/IP is reported:
- **EMAIL** — a lone address matches at full confidence (80), so it is reported and
  also contributes to the composite PII profiles when other PII is present. (Whether a
  lone email warrants action is left to the policy layer — the engine reports it, it
  doesn't decide.)
- **IP_ADDRESS** — a single IP is a low-confidence match (60, below the
  high-confidence threshold); ≥2 IPs get an instance boost to ≥65 and are reported
  high-confidence.

Note: with the move to the report model (DECISIONS.md 2026-07-07), profiles no longer
carry a `verdict_on_match` ceiling — these examples are now purely about *confidence*,
not an action.

### Finding 2 — PDF parsing is a DoS risk on untrusted input
~24 of 1,457 PDFs drove `ledongthuc` to **multi-GB live allocation** (one hit 9.5 GB),
OOM-killing the process. `GOMEMLIMIT` did **not** help (allocations are live). In-process
mitigations (output `LimitReader`, recover) don't stop it. **Mitigation: process
isolation.** `--scan --isolate` (default on) inspects each file in a child process with
an **RSS cap + timeout watchdog**; a bomb only kills the child (recorded as
`readable: false` / isolated), parent stays at ~17 MB. This mirrors the production
requirement to sandbox untrusted
text extraction (the spec's stripped-down MuPDF build). Per-file scan latency is still
read from the child's JSON, so the numbers stay accurate.

### Behaviour: unsupported vs encrypted
Both a plain unsupported/binary type (image, exe) and an *encrypted*/corrupt file are
reported as `readable: false` (no body inspected) — the distinction survives only in
the `note` (unsupported vs encrypted). The policy layer decides what, if anything, an
unreadable file warrants — previously a binary ALLOWed and an encrypted doc ESCALATEd;
that action split now lives in policy, not here.

## Notes / divergences from the illustrative spec corpus
- Our data types roll into **profiles**, which differs from the spec's illustrative
  per-dataset table. (Standalone `EMAIL` and `IP_ADDRESS` profiles were later added
  so a lone email/IP is still reported — see Finding 1.)
- SSN validity uses a `ssn_check` validator instead of regex lookahead (RE2 has no
  lookahead) — semantically equivalent; see DECISIONS.md.
- The engine reports matches only; there is no ALLOW/BLOCK/ESCALATE. Actions are a
  separate policy-engine concern (DECISIONS.md 2026-07-07).
