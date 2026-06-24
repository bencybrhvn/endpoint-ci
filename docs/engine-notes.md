# Engine notes & findings (PoC)

The local inspection engine, run against the synthetic corpus. PoC **reports**
verdicts — it never enacts blocking.

## Pipeline

```
file → detect format (magic bytes)
     → extract text (plaintext direct · OOXML via archive/zip · PDF text layer)
     → prefilter (Aho-Corasick literals + needs-digit, one pass → skip detectors)
     → scan (31 leaf detectors: regex + dictionary, run across cores, match-capped)
       in priority-ordered batches; re-evaluate profiles after each batch and
       short-circuit once the verdict is decided
     → confidence model (base +validator +keyword +instances)
     → profile evaluation (and/or/min/min_validated over fired detectors)
     → verdict: BLOCK / ESCALATE / ALLOW
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
  - Encrypted/legacy/unsupported/parse failure → **ESCALATE** with a note; never
    crashes the caller (spec §10 fail-gracefully).
- Extracted text is capped (default 5 MB) and flagged `truncated`.

### Size gate + head/tail extraction (spec §4.3)

Files above the **size gate** (`MaxFileBytes`, default 16 MB; CLI `--max-file-mb`)
are reduced to their **head + tail windows** (`HeadTailWindow`, default 64 KB each)
— the middle is not inspected, so cost is bounded regardless of file size. For
plaintext the gate is applied on the raw bytes (we never build a huge string).
The result is flagged `Partial`.

**Coverage-aware verdict:** partial (or truncated) extraction means a clean
result is only "clean for what we saw", so the engine **escalates instead of
ALLOWing** — the unseen middle isn't silently passed. A profile/label that *does*
fire in the head/tail still BLOCKs. (Demo: a 21 MB clean file with a 1 MB gate →
131 KB inspected, ESCALATE, ~18 ms.) The metadata label fast-path always runs on
the full container (docProps are tiny), so labels are caught even under the gate.

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
  label is machine-written → authoritative → **upgrades the verdict to BLOCK**.
  The fast-path runs **even when text extraction fails**, so a labelled-but-
  unparseable document is still caught (BLOCK) rather than merely escalated.
- **Body fallback** — scans already-extracted text for *distinctive* markings
  (multi-word or all-caps, case-sensitive: `COMPANY CONFIDENTIAL`, `TOP SECRET`,
  `INTERNAL USE ONLY`…) so the bare word "Confidential" in prose doesn't trip it.
  A body marking → at least **ESCALATE**.

Markers come from the `label_markers` section of `config/rules.json`. Labels appear
in the verdict's `labels[]` with their `source` (`metadata`/`body`). Verified:
`labeled.docx` (OOXML MSIP property)→BLOCK, `labeled.pdf` (PDF XMP MSIP label)→
BLOCK, `footer_marked.docx` (body marking)→ESCALATE.

Verified end to end (`go test`): `hipaa.docx`→PHI/PII, `pci.xlsx`→PCI/Financial,
`financial.pptx`→Financial, `pii.pdf`→US_PII, `clean.docx`→ALLOW,
`legacy.doc` (OLE)→ESCALATE.

Packages: `internal/rules` (load + RE2 compat classify + per-detector pattern
combine), `internal/validators` (luhn/iban/aba/vin/ssn/ein/npi/dea),
`internal/scan` (detectors + confidence), `internal/profile` (composition),
`internal/engine` (orchestration + verdict). CLI: `cmd/ch-inspect`.

## Verdict logic

- **BLOCK** — a profile matched with confidence ≥ `block_threshold` (65).
- **ESCALATE** — a profile matched but only below the block threshold (uncertain;
  e.g. a valid SSN with no surrounding context keyword). Let cloud decide.
- **ALLOW** — no profile matched (detector findings may still be reported).

## Corpus results (10/10 as expected — `go test ./...`)

| File | Verdict | Profiles |
|---|---|---|
| pci_card.txt | BLOCK | PCI, FINANCIAL, US_PII |
| financial_iban.txt | BLOCK | FINANCIAL |
| ssn_context.txt | BLOCK | US_PII |
| ssn_nocontext.txt | **ESCALATE** | US_PII (low confidence) |
| pii_multi.txt | BLOCK | US_PII (email + phone) |
| hipaa.txt | BLOCK | US_PII, PHI_HIPAA |
| secrets.txt | BLOCK | SECRETS |
| card_invalid_luhn.txt | ALLOW | — (Luhn rejected the FP) |
| names_only.txt | ALLOW | — (one detector ≠ ≥2 distinct PII) |
| clean.txt | ALLOW | — |

These confirm the design intent: validators kill FPs (invalid Luhn → ALLOW),
context drives BLOCK vs ESCALATE (SSN with/without keyword), and a lone weak
signal (names only) cannot raise a profile.

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
   any profile threshold, so verdicts are unchanged.
5. **Parallel detector scan** — detectors are read-only and independent, so they
   run across `NumCPU` goroutines. Per-file latency drops ~Ncore×; CPU is a brief
   burst, not steady-state (the ≤3% CPU budget is amortised over an event stream).
   Race-clean (`go test -race`).
6. **Early-exit short-circuit** — detectors run in priority-ordered batches
   (validator-backed/strong first). After each batch we re-evaluate profiles; once
   a BLOCK-confidence verdict is decided (or matches saturate `max_total_matches`),
   we stop — remaining detectors can't change the disposition. On saturated input
   this skips most detectors (allocs dropped ~65×). **Trade-off:** a short-circuited
   verdict is disposition-correct but may report a *partial* profile list (we
   stopped once we knew it was bad). Detection-completeness tests run with
   early-exit disabled; the fast path is covered by `TestEarlyExit`.

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
throughput, verdict + file-type breakdowns, slowest files, heap + peak RSS, optional
`--cpuprofile`/`--memprofile`/`--csv`. Dot-dirs are skipped by default.

Run against a labelled policy test corpus (**3,735 files / 529 MB**):
- **Latency** p50 758µs, p95 3.3ms, p99 18ms — well within budget (the headline
  mean/max are skewed by isolated-timeout files, below).
- **Parent peak RSS 17.5 MB.**
- **Accuracy** (vs `Matches`/`NonMatches` ground truth): ~100% recall on the data
  types we implement (Credit_Card, Canada_SIN, SWIFT, FR/ES/IT/CA PII…); overall
  recall is lower only because the corpus spans ~all policies incl. ~22 types we
  don't implement (medical diagnoses, Australia TFN/IHI, AML…).

### Finding 1 — single-signal types didn't BLOCK (now addressed)
`IP_Address`-only / email-only files originally scored 0%: the detector fired but no
*profile* was satisfied by one weak signal. **Resolved** by adding standalone `EMAIL`
and `IP_ADDRESS` profiles. Confidence drives severity: an email (conf 80) → BLOCK; a
single IP (conf 60) → ESCALATE; ≥2 IPs (instance boost → 65+) → BLOCK. Trade-off: a
standalone email profile flags any document containing an address — intended (mirrors
the cloud "E-mail Address" dataset), tune `base_confidence`/`block_threshold` to soften.

### Finding 2 — PDF parsing is a DoS risk on untrusted input
~24 of 1,457 PDFs drove `ledongthuc` to **multi-GB live allocation** (one hit 9.5 GB),
OOM-killing the process. `GOMEMLIMIT` did **not** help (allocations are live). In-process
mitigations (output `LimitReader`, recover) don't stop it. **Mitigation: process
isolation.** `--scan --isolate` (default on) inspects each file in a child process with
an **RSS cap + timeout watchdog**; a bomb only kills the child (recorded ESCALATE),
parent stays at ~17 MB. This mirrors the production requirement to sandbox untrusted
text extraction (the spec's stripped-down MuPDF build). Per-file scan latency is still
read from the child's JSON, so the numbers stay accurate.

### Behaviour: unsupported vs encrypted
A plain unsupported/binary type (image, exe) → **ALLOW** (no text to inspect, not our
content). Only *encrypted*/corrupt (likely a doc we can't read) → **ESCALATE**.

## Notes / divergences from the illustrative spec corpus
- We have **no standalone Email/SSN datasets** — those roll into profiles. A pure
  email list therefore ALLOWs (no profile needs a single email). This is by design
  for our profile set, and differs from the spec's illustrative per-dataset table.
- SSN validity uses a `ssn_check` validator instead of regex lookahead (RE2 has no
  lookahead) — semantically equivalent; see DECISIONS.md.
