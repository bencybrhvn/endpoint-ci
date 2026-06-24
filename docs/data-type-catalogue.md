# Supported Data-Type Catalogue (MVP scoping)

> Status: **MVP scope LOCKED (2026-06-24).** MVP v0 = **Tier 1** (6 universal, validator-backed types). Tier 2 (US + UK identifiers) is the agreed next expansion; Tier 3 (technical secrets) after that. The three excluded classes below are confirmed out of MVP.

## LOCKED MVP v0 — supported data types

We author the RE2 pattern + validator ourselves for each of these six:

| # | Data type | Validator | Notes |
|---|---|---|---|
| 1 | Credit / debit card number | ✅ Luhn | 13–19 digit major networks |
| 2 | IBAN | ✅ mod-97 | country code + length table |
| 3 | ABA routing number | ✅ checksum | 9-digit, weighted mod-10 |
| 4 | SWIFT / BIC code | format | 8 or 11 alnum |
| 5 | Email address | format | pragmatic RFC subset |
| 6 | IP address (v4 / v6) | format | exclude trivial FPs (e.g. version strings) |

**Agreed next phases (not in v0):** Tier 2 = US + UK + global geo focus (US SSN, EIN, DEA, NPI; UK NINO; NA phone). Tier 3 = technical secrets (API/cloud keys, PEM private keys, JWTs).

## What the source policies actually give us

The Cyberhaven policy export (`ch-ci-policy-gen/`) is a **taxonomy, not a pattern library**:

- **294** XML policy templates (`GeneratedPolicies/*.xml`) — each composes detection primitives with boolean AND/OR logic + confidence thresholds + category metadata.
- **278** detection primitives catalogued in `nucleuz-policies.json` — each has `id`, `name`, `description`, and `rules_ids` (UUIDs).
- **The `rules_ids` point to regex/classification definitions we do NOT have.** No patterns are present anywhere in the export.

**Consequence:** for any data type we choose to support, **we author the RE2 pattern (and validator) ourselves.** The policies tell us *what* Cyberhaven detects and how detections are grouped; they don't tell us *how* to match.

### Structure of the taxonomy

- **6 DataType buckets:** `PII_Personal_Data` (150 policies), `Sensitive_Personal_Data` (84), `PHI_Medical` (44), `Technical_Keys_Secrets` (11), `HR_Business_Specific` (7), `Financial_PCI` (7).
- **63** policies are atomic (single classification rule); **231** are composite/group (country bundles, compliance frameworks).

## MVP framing (per the brief)

Detect **data types only** — the underlying identifiable data — **not** the composite "groups". So we explicitly set aside, for MVP:

| Excluded class | Examples | Why out of MVP |
|---|---|---|
| Country PII / Sensitive bundles | `*_PII`, `*_Sensitive_Data` (≈190 files) | These are *bundles* of atomic identifiers per country, not data types themselves. |
| Compliance frameworks | GDPR, HIPAA, SOC 2, ISO 27001, NIST 800-53/171, PCI-DSS, SOX, GLBA, FERPA, all US state privacy acts | Regulatory groupings / document classification, not data types. |
| Keyword / semantic concepts | ~40 Medical Diagnosis lists, Harassment, Ethics, Bribery, AML, MNPI, Stock Advice, Resumes, Proposals, COVID | No structured pattern — need dictionaries/NLP, not regex. Revisit post-MVP. |

That leaves the **atomic, structured, locally-patternable identifiers** as the MVP candidate pool.

## Proposed MVP supported data types (candidate list)

Tiered by detection confidence. ✅ = has a deterministic validator (very low false-positive rate).

### Tier 1 — Universal, structured, validator-backed (highest precision)
| Data type | Source policy | Bucket | Validator |
|---|---|---|---|
| Credit / debit card number | Credit/Debit Card Number | Financial_PCI | ✅ Luhn |
| IBAN | (Bank Account — generic) | Financial_PCI | ✅ mod-97 |
| ABA routing number | ABA Routing Transit Number | Financial_PCI | ✅ checksum |
| SWIFT / BIC code | SWIFT Codes | Financial_PCI | format |
| Email address | E-mail Address | PII | format |
| IP address (v4/v6) | IP Address | PII / Technical | format |

### Tier 2 — Region-specific but high-value & structured
| Data type | Source policy | Bucket | Validator |
|---|---|---|---|
| US SSN / Taxpayer ID | US SSN | PII | range rules |
| US EIN | US EIN | PII | prefix table |
| US DEA number | US DEA Number | PHI/PII | ✅ checksum |
| US NPI | US NPI | PHI | ✅ Luhn-based |
| Canada SIN | Canada SIN | PII | ✅ Luhn |
| UK NINO | UK NINO | PII | format |
| North American phone | NA Telephone Number | PII | format |

### Tier 3 — Technical secrets (high security value, very patternable)
| Data type | Source policy | Bucket | Validator |
|---|---|---|---|
| API keys / cloud keys (e.g. AWS) | Software Keys and Tokens | Technical_Keys_Secrets | prefix + entropy |
| Private keys (PEM blocks) | Software Keys and Tokens | Technical_Keys_Secrets | marker |
| JWTs / bearer tokens | Authentication | Technical_Keys_Secrets | structure |

### Debatable candidates (decide explicitly)
Date of Birth · US/UK passport · postal/mailing address · national IDs (France, Italy Codice Fiscale, Switzerland) · generic bank account number · magnetic-stripe track data · health insurance number (generic).
> These are either context-heavy (DOB, address), highly region-fragmented (national IDs, driver's licences), or high false-positive (generic bank account) — include only if specifically wanted.

## Selection criteria (how we decide what makes the list)

1. **Structurally patternable** — has a regular, recognisable format (rules out keyword concepts).
2. **Validator available** — a checksum/algorithm to kill false positives (preferred, not required).
3. **RE2-compatible** — expressible without lookahead/lookbehind/backreference (Go `regexp`). Range-guarded patterns (e.g. SSN) may need rewriting.
4. **High value / prevalence** — common in real egress, matters for DLP.
5. **Low false-positive risk** at endpoint scale (≤3% CPU, runs constantly).

## Decisions (resolved 2026-06-24)
- [x] Exclude all three classes (country bundles, compliance frameworks, keyword concepts) from MVP.
- [x] MVP set = **Tier 1 only** (6 universal validator-backed types).
- [x] Geographic focus for expansion = **US + UK + global** (drives Tier 2).
- [x] Debatable candidates (DOB, passport, address, national IDs, generic bank account, magstripe, health insurance) — **deferred**, none in v0.

## Next step
The list is locked. Build proceeds against exactly these six types: author RE2 patterns + validators, wire the inspection pipeline, and benchmark against the resource budget (≤50 MB, ≤3% CPU, <100 ms for ≤500 KB).
