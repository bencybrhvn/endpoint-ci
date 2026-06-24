# Person-name detection design (dictionary / gazetteer)

Names have no structural pattern, so regex can't find them. We use **lexical
evidence** instead — a dictionary/gazetteer detector (`kind: "dictionary"` in
`config/rules.json`, reference implementation in `tools/name-scan`).

## The core tension

Names overlap with ordinary words. In our lists, ~108 given names (april, austin,
bill, grace…) are also common English words. So:

- **Gazetteer (surnames + given names)** gives *recall* — what looks like a name.
- **High-frequency word list** gives *precision* — but the naive approach fails.

### What didn't work
Penalising any token that appears in a broad 5,000-word common-word list: it
cancelled real names, because `john`/`smith`/`williams` are themselves frequent
tokens and sit inside the top-5k.

### What works: frequency rank, not membership
Use a **tight top-300 high-frequency list**. A token is counted as *name evidence*
only if it is in a name list **and not** in the top-300 words. Word ranks make the
cutoff clean:

| token | word rank | name? | counts as name evidence |
|---|---|---|---|
| will | 32 | surname too | no (high-freq) |
| may | 55 | given/surname | no (high-freq) |
| contact | 69 | — | no |
| john | 372 | given/surname | **yes** |
| smith | 1282 | surname | **yes** |
| jane | 3636 | given | **yes** |

## Scoring

Walk spans of capitalised tokens separated **only by spaces** (sentence
punctuation breaks a span, so "Williams. Contact" is two spans):

```
+2  per name-evidence token
+3  adjacency: >=2 name-evidence tokens in the span
+3  title: span led by / preceded by Mr/Mrs/Ms/Dr/Prof/...
+1  context keyword (name|patient|customer|employee) within 200 chars
fire if score >= 5
```

`John Smith` → 2+2+3 = 7 (fire). `Dr Smith` → 3+2 = 5 (fire). `Will May` (prose) →
both high-freq, 0 evidence → no fire.

## Measured behaviour (reference impl)

- Positives: `Patient John Smith`, `Dr Jane Williams`, `Maria Garcia`,
  `Robert Johnson` → all fire.
- Negatives suppressed: `Will Go Home`, `May Flowers`, `London`, `New York`.
- Residual false positive: **`April Showers`** — lexically identical to a
  first/last name; inherently ambiguous without semantics.

## Why residual FPs are acceptable here

`person_name` is one signal among many. The **profile layer** requires ≥2 distinct
PII detectors (or a strong validated ID) before `US PII` / `PHI/HIPAA` fires, so a
lone noisy name match cannot raise a profile by itself. The two-layer design is
specifically what lets leaf detectors be imperfect.

## Budget

Lists are tiny: surnames 10k + given 4.9k + high-freq 300 ≈ 145 KB on disk; loaded
as sets (or, in production, a bloom filter / FST for lower memory). Lookup is
O(tokens). Comfortably inside the ≤50 MB / fast endpoint budget.

## Post-MVP

- Expand lists (international names; full Census 160k surnames).
- Bloom filter / FST storage for memory.
- Optional compact statistical NER for higher accuracy (adds size/latency —
  weigh against budget).
