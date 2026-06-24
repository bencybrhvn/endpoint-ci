# Endpoint Content Inspection — PoC Build Specification

**For:** Code agent  
**Date:** June 2026  
**Background doc:** `endpoint-content-inspection-eval.md`  
**Input:** Cyberhaven content inspection rules (provided separately as rule definitions)

---

## 1. PoC Objective and Success Criteria

Build a self-contained C library (`ch_local_inspect`) that:

1. Ingests Cyberhaven's existing cloud-side content inspection rule definitions (provided as JSON/YAML) and compiles them into a local RE2 pattern database
2. Accepts a file path or byte buffer and returns a structured verdict: which datasets matched, with what confidence, and whether to ALLOW / BLOCK / ESCALATE
3. Produces match results that use the **same dataset IDs** as the cloud pipeline, so local and remote verdicts on identical content are directly comparable
4. Runs within the resource budget: ≤ 50 MB RAM peak, ≤ 3% CPU on a representative egress event stream

**PoC is complete when:**
- The rule compiler ingests the provided rules and reports how many are RE2-compatible vs. require cloud-only handling
- The scanner correctly identifies PII patterns and label markers in a test corpus of 20+ sample files
- A comparison test confirms that local matches on a plaintext file produce the same dataset IDs as the cloud pipeline would for the same content
- A benchmark confirms <100ms end-to-end latency for files ≤ 500 KB on a 2023-era laptop

**PoC explicitly does NOT include:**
- Integration into the actual sensor binary
- Policy enforcement logic (block/allow decisions are reported, not enacted)
- Any network calls — this is a purely local, offline library
- OCR, legacy Office formats (.doc/.xls), or password-protected files

---

## 2. Rule Reuse Design — The Core Architectural Principle

This is the most important design decision in the PoC. The cloud and local inspection layers **must share the same rule source**. Maintaining two rule sets — one for cloud, one for local — will diverge over time and create unexplainable detection discrepancies.

### 2.1 Rule Source of Truth

The Cyberhaven cloud pipeline already defines content inspection rules as **datasets** — structured definitions containing:
- A stable `dataset_id` (UUID)
- A `dataset_name` (human-readable)
- One or more `rules`, each containing:
  - A `rule_id`
  - A `pattern` (regex string, PCRE-compatible as used by the cloud engine)
  - An optional `validators` array (e.g., `luhn_check`, `checksum_iban`) for post-match validation
  - A `min_confidence` threshold
  - Optional `keywords` (required context words near a match to reduce FP)

The provided rules file will be in this format. **Treat it as read-only input.** The PoC should not modify or redefine patterns — it should consume them as-is.

### 2.2 RE2 Compatibility Layer

The cloud engine uses PCRE-compatible regex. RE2 does not support lookaheads, lookbehinds, or backreferences. Most structured PII patterns (SSN, CCN, IBAN, email) are RE2-compatible. Some patterns using `(?=...)` or `(?<!...)` are not.

The rule compiler must:

1. **Attempt to compile each pattern with RE2**
2. **Classify each rule** into one of three buckets:
   - `LOCAL_CAPABLE`: Pattern compiles cleanly with RE2, no unsupported features
   - `LOCAL_APPROXIMATE`: Pattern has minor PCRE features that can be rewritten to RE2 without changing detection semantics (e.g., `(?i)` case-insensitive flag → RE2 equivalent `(?i)`)
   - `CLOUD_ONLY`: Pattern uses lookaheads, backreferences, or other features with no safe RE2 equivalent — skip for local scanning, always escalate to cloud for these datasets

3. **Emit a compatibility report** at startup:
   ```
   Rule compilation report:
     Total rules:        143
     LOCAL_CAPABLE:      118  (82.5%)
     LOCAL_APPROXIMATE:   19  (13.3%)
     CLOUD_ONLY:           6   (4.2%)

   CLOUD_ONLY datasets (will not run locally):
     - dataset_id: abc123  name: "Custom SWIFT Code Detector"   reason: backreference \1
     - dataset_id: def456  name: "Org SSO Token Pattern"        reason: lookbehind (?<!)
   ```

4. **Never silently drop a rule.** Every CLOUD_ONLY rule must appear in the compatibility report with the specific unsupported feature noted. This ensures the operator knows the exact coverage gap.

### 2.3 Verdict-to-Dataset Mapping

When a local scan produces a match, the verdict must reference the original `dataset_id` and `rule_id` from the provided rules. This is what enables direct comparison with cloud verdicts:

```json
{
  "verdict": "BLOCK",
  "file": "Q3_compensation_report.docx",
  "file_size_bytes": 84210,
  "scan_duration_ms": 23,
  "matches": [
    {
      "dataset_id": "7f3a1c2b-...",
      "dataset_name": "US Social Security Numbers",
      "rule_id": "rule_001",
      "match_count": 4,
      "confidence": 0.95,
      "validators_passed": [],
      "scan_path": "local"
    }
  ],
  "escalate_datasets": ["abc123"],
  "local_coverage_note": "2 CLOUD_ONLY datasets were not evaluated locally"
}
```

The `scan_path: "local"` field allows downstream systems to distinguish local verdicts from cloud verdicts on the same file. A cloud re-scan of the same file should produce `scan_path: "cloud"` matches on the same `dataset_id` values — drift between local and cloud on the same content is a signal that pattern rewriting introduced semantic change.

---

## 3. PoC Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       ch_local_inspect                          │
│                                                                 │
│  ┌──────────────────┐    ┌────────────────────────────────────┐ │
│  │  Rule Compiler   │    │         Inspector                  │ │
│  │                  │    │                                    │ │
│  │  rules.json/yaml │    │  ch_inspect_file(path, opts)       │ │
│  │       │          │    │         │                          │ │
│  │  RE2 compat      │    │  ┌──────▼──────────────────────┐   │ │
│  │  check + classify│    │  │  1. Format detector          │   │ │
│  │       │          │    │  │     (magic bytes → type)    │   │ │
│  │  Compiled RE2    │    │  └──────┬──────────────────────┘   │ │
│  │  database        ├───►│         │                          │ │
│  │  (startup-time)  │    │  ┌──────▼──────────────────────┐   │ │
│  │                  │    │  │  2. Text extractor           │   │ │
│  │  Keyword trie    ├───►│  │     plaintext / OOXML / PDF  │   │ │
│  │  (label strings) │    │  └──────┬──────────────────────┘   │ │
│  └──────────────────┘    │         │                          │ │
│                          │  ┌──────▼──────────────────────┐   │ │
│                          │  │  3. RE2 multi-pattern scan  │   │ │
│                          │  │     → dataset_id matches    │   │ │
│                          │  └──────┬──────────────────────┘   │ │
│                          │         │                          │ │
│                          │  ┌──────▼──────────────────────┐   │ │
│                          │  │  4. Post-match validators   │   │ │
│                          │  │     (Luhn, IBAN checksum)   │   │ │
│                          │  └──────┬──────────────────────┘   │ │
│                          │         │                          │ │
│                          │  ┌──────▼──────────────────────┐   │ │
│                          │  │  5. Label/marker detector   │   │ │
│                          │  │     (metadata + head/tail)  │   │ │
│                          │  └──────┬──────────────────────┘   │ │
│                          │         │                          │ │
│                          │  ┌──────▼──────────────────────┐   │ │
│                          │  │  6. Verdict builder         │   │ │
│                          │  │     ALLOW/BLOCK/ESCALATE    │   │ │
│                          │  └─────────────────────────────┘   │ │
│                          └────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Component Specifications

### 4.1 Rule Compiler (`rule_compiler.c / .h`)

**Input:** Path to rules JSON/YAML file (format described in Section 2.1)  
**Output:** In-memory compiled state: RE2 database + keyword trie + validator map  
**Called once at library init**

```c
typedef enum {
    RULE_LOCAL_CAPABLE     = 0,
    RULE_LOCAL_APPROXIMATE = 1,
    RULE_CLOUD_ONLY        = 2,
} RuleLocalStatus;

typedef struct {
    char     dataset_id[64];
    char     dataset_name[256];
    char     rule_id[64];
    char     pattern_original[4096];  // from rules file, unmodified
    char     pattern_re2[4096];       // RE2-adapted version (may == original)
    RuleLocalStatus status;
    char     skip_reason[512];        // populated if CLOUD_ONLY
    char**   validators;              // e.g., {"luhn_check", NULL}
    char**   keywords;                // required context words, if any
    int      min_confidence;          // 0–100
} CompiledRule;

typedef struct {
    CompiledRule* rules;
    int           rule_count;
    int           local_capable_count;
    int           local_approximate_count;
    int           cloud_only_count;
    // RE2 compiled database handle (opaque)
    void*         re2_db;
    // Keyword trie for label marker detection (opaque)
    void*         label_trie;
} RuleDatabase;

int  ch_rules_load(const char* rules_path, RuleDatabase** out_db);
void ch_rules_print_report(const RuleDatabase* db);
void ch_rules_free(RuleDatabase* db);
```

**RE2 pattern rewriting rules (apply in order, bail to CLOUD_ONLY if unable):**
1. `(?i)` at start → acceptable, RE2 supports it
2. `(?:...)` non-capturing group → acceptable
3. `\b` word boundary → acceptable  
4. `(?=...)` lookahead → CLOUD_ONLY, log unsupported feature
5. `(?<=...)` lookbehind → CLOUD_ONLY
6. `(?<!...)` negative lookbehind → CLOUD_ONLY
7. `\1` backreference → CLOUD_ONLY

Log a warning (not an error) for LOCAL_APPROXIMATE rewrites so the operator can review.

### 4.2 Format Detector (`format_detect.c / .h`)

**Input:** File path or first 512 bytes of buffer  
**Output:** `FileType` enum

```c
typedef enum {
    FILE_TYPE_UNKNOWN     = 0,
    FILE_TYPE_PLAINTEXT   = 1,
    FILE_TYPE_CSV         = 2,
    FILE_TYPE_DOCX        = 3,  // OOXML
    FILE_TYPE_XLSX        = 4,
    FILE_TYPE_PPTX        = 5,
    FILE_TYPE_PDF         = 6,
    FILE_TYPE_ENCRYPTED   = 7,  // detected but unreadable
    FILE_TYPE_UNSUPPORTED = 8,  // out of scope for v1
} FileType;

FileType ch_detect_format(const char* path);
```

Detection logic:
- PDF: `%PDF` at offset 0
- OOXML: ZIP magic `PK\x03\x04` at offset 0, then check for `[Content_Types].xml` entry
- Encrypted Office: ZIP magic but `EncryptionInfo` entry present
- Plaintext/CSV: UTF-8 or ASCII content with no binary markers
- Unknown → `FILE_TYPE_UNSUPPORTED`

### 4.3 Text Extractor (`text_extract.c / .h`)

**Input:** File path, `FileType`, extraction config  
**Output:** Null-terminated text buffer (caller-owned), byte count

```c
typedef struct {
    size_t max_bytes;        // cap on extracted text; default 5 MB
    int    head_tail_only;   // if 1, extract first + last 64 KB only
    int    include_metadata; // if 1, include document property text
} ExtractConfig;

typedef struct {
    char*  text;             // extracted plaintext, caller must free
    size_t text_len;
    int    truncated;        // 1 if max_bytes was hit
    char   error[256];       // non-empty on extraction failure
} ExtractResult;

ExtractResult ch_extract_text(const char* path, FileType type,
                              const ExtractConfig* cfg);
void          ch_extract_free(ExtractResult* r);
```

**Per-format extraction:**

*Plaintext / CSV:* Read directly into buffer up to `max_bytes`. No library needed.

*OOXML (DOCX/XLSX/PPTX):* Use **miniz** (single-header, MIT, ~50 KB):
- For DOCX: extract and parse `word/document.xml`, `word/header*.xml`, `word/footer*.xml`, `docProps/custom.xml`
- For XLSX: extract `xl/sharedStrings.xml` (cell values live here)
- For PPTX: extract `ppt/slides/slide*.xml`
- Strip XML tags with a simple state machine (no full DOM parse needed) — output raw text tokens
- Metadata path: always parse `docProps/custom.xml` regardless of `head_tail_only` flag

*PDF (text layer):* Use **MuPDF** in text-extraction-only mode:
- Call `fz_new_document_from_file` → `fz_load_page` → `fz_new_stext_page`
- Extract as plain text; do NOT render
- If `head_tail_only`, extract page 1 + last page only, then check XMP metadata block
- MuPDF should be compiled with rendering backends disabled (`HAVE_CAIRO=no`, etc.) to reduce binary size

*Note for PoC:* MuPDF can be linked dynamically (so it doesn't bloat the PoC binary for evaluation purposes). For production integration, static linking with stripped-down build flags is the target.

### 4.4 RE2 Multi-Pattern Scanner (`scanner.c / .h`)

**Input:** Text buffer from extractor, compiled `RuleDatabase`  
**Output:** Array of `MatchResult`

```c
typedef struct {
    char   dataset_id[64];
    char   rule_id[64];
    int    raw_match_count;      // total regex hits
    int    validated_match_count; // hits that passed validators
    float  confidence;           // 0.0–1.0
    int    keyword_context_found; // 1 if required keywords present nearby
} MatchResult;

typedef struct {
    MatchResult* matches;
    int          match_count;
    long         scan_duration_us;
} ScanResult;

ScanResult ch_scan(const char* text, size_t text_len,
                   const RuleDatabase* db);
void       ch_scan_free(ScanResult* r);
```

**Scanning strategy:**

1. Run RE2 `FindAllSubmatch` across the text buffer for all LOCAL_CAPABLE and LOCAL_APPROXIMATE patterns in a single pass (RE2 set matching)
2. For each raw match, run the rule's `validators`:
   - `luhn_check`: validate matched string passes Luhn algorithm
   - `checksum_iban`: validate IBAN country code + length + mod-97 checksum
   - `checksum_aba`: validate ABA routing number checksum
3. Check `keywords`: if the rule requires context words, verify at least one keyword appears within 200 characters of the match
4. Compute per-rule confidence:
   - Start at `min_confidence` from rule definition
   - Boost +10 if validator passed
   - Boost +5 if keyword context found
   - Boost +5 for each additional match instance (up to 3 boosts)
   - Cap at 1.0

**Implementation note:** RE2 set matching (compiling all patterns into one `RE2::Set`) is the efficient approach — it runs all patterns in a single pass rather than looping per-pattern. Use `RE2::Set::Match()` which returns the set of matching pattern indices.

### 4.5 Label / Marker Detector (`label_detect.c / .h`)

**Input:** File path, `FileType`, keyword list from `RuleDatabase`  
**Output:** Array of `LabelMatch`

```c
typedef struct {
    char   label_string[256];   // matched label text, e.g. "CONFIDENTIAL"
    char   detection_source[64]; // "metadata", "header", "footer", "body_prefix"
    char   dataset_id[64];       // dataset this label string belongs to
} LabelMatch;

typedef struct {
    LabelMatch* matches;
    int         match_count;
} LabelResult;

LabelResult ch_detect_labels(const char* path, FileType type,
                              const RuleDatabase* db);
void        ch_label_free(LabelResult* r);
```

**Detection paths (execute in order, stop early if match found):**

1. **Metadata fast path** (no text extraction, microseconds):
   - OOXML: open ZIP, read `docProps/custom.xml` only, parse XML, check property names and values against label keyword list
   - PDF: read XMP metadata block (starts at `<?xpacket`), string-search for label keywords
   - Look for AIP label properties: `MSIP_Label_*`, `Sensitivity`, `Classification`, `DataClass` and similar

2. **Header/footer path** (partial extraction):
   - OOXML: read `word/header1.xml` and `word/footer1.xml` only
   - PDF: extract text from first and last page only (1-page scan via MuPDF)
   - String-match extracted text against label keyword list (case-insensitive Aho-Corasick via the keyword trie)

3. **Body prefix/suffix** (fallback, only if steps 1–2 find nothing):
   - Take first 4 KB and last 4 KB of extracted body text
   - Run same keyword trie match

The label keyword list should come from the same rules file, under a `label_markers` section (see Section 5). This ensures label strings defined in cloud-side datasets are consistent with what's matched locally.

### 4.6 Verdict Builder (`verdict.c / .h`)

```c
typedef enum {
    VERDICT_ALLOW    = 0,
    VERDICT_BLOCK    = 1,
    VERDICT_ESCALATE = 2,
} VerdictCode;

typedef struct {
    VerdictCode  verdict;
    char         file_path[4096];
    size_t       file_size_bytes;
    FileType     file_type;
    long         total_duration_ms;
    MatchResult* regex_matches;
    int          regex_match_count;
    LabelMatch*  label_matches;
    int          label_match_count;
    char**       escalate_dataset_ids; // CLOUD_ONLY datasets not evaluated
    int          escalate_count;
    char         scan_path[16];       // always "local" from this library
} Verdict;

Verdict ch_build_verdict(const ScanResult* scan,
                         const LabelResult* labels,
                         const RuleDatabase* db,
                         const VerdictConfig* cfg);
```

**Default verdict logic (configurable via `VerdictConfig`):**
- BLOCK if: any regex match with `validated_match_count >= 1` AND `confidence >= 0.85`
- BLOCK if: any label match with `detection_source == "metadata"` (high-confidence — label is machine-written, not user-visible text)
- ESCALATE if: any CLOUD_ONLY dataset is relevant to this file type (i.e., cloud hasn't seen it yet), OR file contains encrypted content the sensor cannot read
- ESCALATE if: regex match exists but `confidence < 0.85` (uncertain — let cloud decide)
- ALLOW: no matches, no CLOUD_ONLY applicable datasets

**Key constraint:** The verdict builder must NOT make irreversible decisions. In the PoC, all verdicts are reported and logged — no actual blocking occurs. The output is consumed by the test harness.

---

## 5. Rule Input Format

The code agent should expect the provided rules in the following JSON structure. Adapt parsing if the actual format differs — the key requirement is that `dataset_id` and `rule_id` values pass through unmodified to match results.

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-06-24T00:00:00Z",
  "datasets": [
    {
      "dataset_id": "7f3a1c2b-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
      "dataset_name": "US Social Security Numbers",
      "enabled": true,
      "rules": [
        {
          "rule_id": "rule_001",
          "description": "SSN with or without dashes",
          "pattern": "\\b(?!000|666|9\\d{2})\\d{3}[-\\s]?(?!00)\\d{2}[-\\s]?(?!0000)\\d{4}\\b",
          "min_confidence": 70,
          "validators": [],
          "keywords": ["ssn", "social security", "taxpayer"]
        }
      ]
    },
    {
      "dataset_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "dataset_name": "Payment Card Numbers",
      "enabled": true,
      "rules": [
        {
          "rule_id": "rule_001",
          "description": "16-digit card number, various formats",
          "pattern": "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\\b",
          "min_confidence": 60,
          "validators": ["luhn_check"],
          "keywords": ["card", "visa", "mastercard", "payment", "cc"]
        }
      ]
    }
  ],
  "label_markers": [
    {
      "dataset_id": "label-001",
      "dataset_name": "Microsoft Sensitivity Labels",
      "strings": [
        "Highly Confidential", "Confidential", "General", "Public",
        "MSIP_Label", "Sensitivity"
      ],
      "metadata_properties": ["MSIP_Label_", "Sensitivity", "Classification"]
    },
    {
      "dataset_id": "label-002",
      "dataset_name": "Custom Org Classification Markers",
      "strings": [
        "INTERNAL USE ONLY", "PROPRIETARY", "TOP SECRET",
        "FOR INTERNAL USE", "RESTRICTED"
      ],
      "metadata_properties": ["DataClass", "DocSensitivity"]
    }
  ]
}
```

---

## 6. Build and Project Structure

```
ch_local_inspect/
├── CMakeLists.txt
├── README.md
├── include/
│   └── ch_inspect.h          # single public header for the library
├── src/
│   ├── ch_inspect.c          # main entry point: ch_inspect_file()
│   ├── rule_compiler.c       # Section 4.1
│   ├── format_detect.c       # Section 4.2
│   ├── text_extract.c        # Section 4.3
│   ├── scanner.c             # Section 4.4
│   ├── label_detect.c        # Section 4.5
│   ├── verdict.c             # Section 4.6
│   └── validators.c          # luhn_check, iban_checksum, aba_checksum
├── third_party/
│   ├── miniz/                # miniz.h + miniz.c (single-file ZIP, MIT)
│   ├── re2/                  # git submodule: github.com/google/re2
│   └── mupdf/                # git submodule or system dep (text path only)
├── tools/
│   └── ch_inspect_cli.c      # standalone CLI: ch_inspect_cli <rules.json> <file>
└── tests/
    ├── test_rule_compiler.c  # unit: RE2 compatibility classification
    ├── test_scanner.c        # unit: regex match + validator correctness
    ├── test_label_detect.c   # unit: metadata + header/footer detection
    ├── test_latency.c        # benchmark: 500 files, measure p50/p95/p99
    ├── test_consistency.c    # integration: compare local vs. expected cloud IDs
    └── corpus/               # test files (20+ samples, see Section 7)
```

**Build dependencies:**
- CMake ≥ 3.20
- C17 compiler (clang or gcc)
- RE2 (via submodule or `brew install re2` / `apt install libre2-dev`)
- MuPDF (system package `libmupdf-dev` for PoC; static build for production)
- miniz (bundled, single header)

**CMake targets:**
- `ch_local_inspect` — shared library (`.so` / `.dylib`)
- `ch_inspect_cli` — CLI tool for manual testing
- `ch_inspect_tests` — test suite (CTest)

---

## 7. Test Corpus and Test Plan

### 7.1 Test Corpus (build into `tests/corpus/`)

The code agent should generate synthetic test files — do NOT use real PII. Create:

| File | Content | Expected outcome |
|---|---|---|
| `ssn_plaintext.txt` | 5 fake SSNs in paragraph text | BLOCK, dataset "US SSN" |
| `ssn_no_context.txt` | 5 SSNs with no surrounding keywords | ESCALATE (low confidence) |
| `ccn_with_luhn.txt` | 3 valid Luhn CCNs | BLOCK, dataset "Payment Card Numbers" |
| `ccn_invalid_luhn.txt` | 3 numbers matching CCN regex but failing Luhn | ALLOW (validator eliminated FP) |
| `iban_doc.txt` | 2 IBAN strings | BLOCK, dataset "IBAN" (if in rules) |
| `email_list.csv` | 50 email addresses | BLOCK, dataset "Email Addresses" |
| `confidential.docx` | OOXML doc with "CONFIDENTIAL" footer | BLOCK, label match |
| `sensitivity_label.docx` | OOXML doc with MSIP_Label custom property | BLOCK, metadata path |
| `clean_report.docx` | No sensitive content | ALLOW |
| `mixed.pdf` | PDF with SSN in body text | BLOCK, dataset "US SSN" |
| `pdf_labeled.pdf` | PDF with Confidential watermark text | BLOCK, label match |
| `pdf_clean.pdf` | PDF with financial tables, no PII | ALLOW |
| `encrypted.docx` | Password-protected OOXML | ESCALATE (encrypted) |
| `large_file.pdf` | PDF > 5 MB | Handled by size gate, not inspected inline |
| `false_positive_fin.txt` | Financial doc with many 9-digit numbers but no SSNs | ALLOW (context keyword mismatch) |

### 7.2 Consistency Test

This is the most important test for validating the rule reuse architecture.

For each test file, the expected verdict is annotated with the `dataset_id` values from the rules file. The test asserts:

```c
// test_consistency.c
void test_ssn_plaintext_consistency() {
    Verdict v = ch_inspect_file("corpus/ssn_plaintext.txt", db, &default_cfg);
    assert(v.verdict == VERDICT_BLOCK);
    // The dataset_id must match what the cloud pipeline would return
    assert(match_contains_dataset_id(&v, "7f3a1c2b-4d5e-6f7a-8b9c-0d1e2f3a4b5c"));
}
```

The expected `dataset_id` values are derived directly from the provided rules file — no hardcoding. If the cloud team re-IDs a dataset, the test updates automatically by re-running against the new rules file. The test is a consistency check, not a functional check.

### 7.3 Latency Benchmark

```c
// test_latency.c
// Run 500 files from corpus through ch_inspect_file(), record duration_ms per file
// Report p50, p95, p99 latency
// Assert p95 < 100ms for files ≤ 500 KB
// Assert p95 < 500ms for files 500 KB – 5 MB
```

### 7.4 RE2 Compatibility Report Validation

```c
// test_rule_compiler.c
// Load provided rules, call ch_rules_load()
// Assert LOCAL_CAPABLE + LOCAL_APPROXIMATE >= 80% of total rules
// Assert every CLOUD_ONLY entry has a non-empty skip_reason
// Assert no pattern classified LOCAL_APPROXIMATE changed match semantics
//   (verify by running both original PCRE2 and rewritten RE2 against 100 sample strings)
```

---

## 8. CLI Tool Usage (for Manual Validation)

The `ch_inspect_cli` tool is the primary manual test interface:

```bash
# Basic scan
./ch_inspect_cli --rules rules.json --file document.docx

# Output:
# {
#   "verdict": "BLOCK",
#   "file": "document.docx",
#   "scan_duration_ms": 18,
#   "matches": [
#     { "dataset_id": "7f3a1c2b-...", "dataset_name": "US SSN",
#       "validated_match_count": 3, "confidence": 0.95, "scan_path": "local" }
#   ]
# }

# Print rule compatibility report only (no file scan)
./ch_inspect_cli --rules rules.json --report

# Benchmark mode: scan all files in a directory, print latency stats
./ch_inspect_cli --rules rules.json --bench ./corpus/
```

---

## 9. What to Hand Off

When the PoC is complete, deliver:

1. **`ch_local_inspect/`** — the full library + CLI + tests (compilable on macOS and Linux)
2. **`compat_report.txt`** — output of `--report` against the provided rules, showing LOCAL_CAPABLE / CLOUD_ONLY breakdown
3. **`benchmark_results.txt`** — latency stats from `--bench` against the test corpus
4. **`consistency_notes.md`** — notes on any datasets where local vs. expected cloud verdict diverged and why

---

## 10. Key Constraints for the Code Agent

- **Do not modify the rule `pattern` field** when classifying as CLOUD_ONLY. Preserve it as-is. Only rewrite for LOCAL_APPROXIMATE cases where the rewrite is semantically equivalent and documented.
- **All `dataset_id` and `rule_id` values must pass through unmodified** from input rules to output verdict JSON. No renaming, hashing, or aliasing.
- **The library must be safe to call from a multithreaded context.** The `RuleDatabase` is read-only after init; `ch_inspect_file` must not write shared state. Use per-call allocations.
- **No network calls, no file system side effects** other than reading the input file.
- **Fail gracefully:** if text extraction fails (corrupt file, unsupported subformat), return `VERDICT_ESCALATE` with an error note — never crash the calling process.
- **The PoC target is correctness and measurability, not production optimization.** Prefer readable code over premature optimization.
