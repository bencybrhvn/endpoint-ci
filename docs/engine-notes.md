# Engine notes & findings (PoC)

The local inspection engine, run against the synthetic corpus. PoC **reports**
verdicts — it never enacts blocking.

## Pipeline

```
file → detect format (magic bytes)
     → extract text (plaintext direct · OOXML via archive/zip · PDF text layer)
     → scan (27 leaf detectors: regex + dictionary)
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

## Performance findings (the budget is the point)

Throughput ≈ **2.8 MB/s** (pure-Go regexp, 27 detectors, per-detector scan):

- Typical files (≤ 8 KB): **~3 ms** — well within the ≤100 ms target.
- 500 KB worst case: **~185 ms** — **~1.8× over** the 100 ms target.

### What we tried
- **Best-effort keyword gating** — skip a context-gated detector's regex if its
  keyword is absent anywhere in the file. Big win (DOB 40 ms → 0.4 ms on text
  with no DOB context). Kept.
- **Per-detector pattern combine** — OR a detector's patterns into one regex.
  Modest win. Kept.
- **Single mega-regex (RE2 set, all detectors in one alternation)** — *reverted*.
  In one alternation, overlapping detectors **steal** each other's matches (the
  generic `\d{9}` ABA detector consumes an NPI's digits, so HIPAA stopped firing),
  and the large submatch arrays made it slower. RE2 set-matching reports *which*
  patterns match, not all per-pattern positions — so it can't replace independent
  per-detector scans without losing matches.

### Path to budget (post-PoC)
- A true multi-pattern matcher returning per-pattern matches without stealing
  (Hyperscan / Vectorscan), or RE2::Set purely as a membership pre-filter to skip
  detectors with zero candidates.
- Reduce overlapping generic-numeric detectors (aba/bank/passport/utr/npi all
  match bare digit runs).
- Cap match enumeration once a profile is already satisfied.
- Size gate + head/tail extraction for very large files (spec `ExtractConfig`).

## Notes / divergences from the illustrative spec corpus
- We have **no standalone Email/SSN datasets** — those roll into profiles. A pure
  email list therefore ALLOWs (no profile needs a single email). This is by design
  for our profile set, and differs from the spec's illustrative per-dataset table.
- SSN validity uses a `ssn_check` validator instead of regex lookahead (RE2 has no
  lookahead) — semantically equivalent; see DECISIONS.md.
