# Engine notes & findings (PoC)

The local inspection engine, run against the synthetic corpus. PoC **reports**
verdicts — it never enacts blocking.

## Pipeline

```
file → detect format (magic bytes)
     → extract text (plaintext direct · OOXML via archive/zip · PDF text layer)
     → prefilter (Aho-Corasick literals + needs-digit, one pass → skip detectors)
     → scan (27 leaf detectors: regex + dictionary, run across cores, match-capped)
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

## Notes / divergences from the illustrative spec corpus
- We have **no standalone Email/SSN datasets** — those roll into profiles. A pure
  email list therefore ALLOWs (no profile needs a single email). This is by design
  for our profile set, and differs from the spec's illustrative per-dataset table.
- SSN validity uses a `ssn_check` validator instead of regex lookahead (RE2 has no
  lookahead) — semantically equivalent; see DECISIONS.md.
