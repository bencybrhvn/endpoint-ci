# Supported Data-Type Catalogue & Detection Model (MVP scoping)

> Status: **two-layer model adopted (2026-06-24).** Breadth (PII, HIPAA, PCI, Financial…) comes not from more leaf patterns but from a **profile layer** that composes leaf detectors — mirroring how the source policies are built. Leaf catalogue expanded accordingly. Scope of profiles + leaf set being finalised (see "Decisions").

## The detection model: detectors + profiles

We cannot pattern-match "PII" or "HIPAA" directly — in the source policies these are **boolean compositions of atomic detectors** (`Or min="2"`, `minCount`, `minUniqueCount`, `minConfidence`). So the engine has two layers:

- **Layer 1 — Detectors (leaf data types):** a single recognisable thing we author a regex (+ optional validator) for. E.g. credit card, SSN, email, ICD-10 code.
- **Layer 2 — Profiles (named concepts):** boolean rollups *over* detector hits that emit a recognisable outcome. E.g. PHI/HIPAA, US PII, PCI, Financial, Secrets. We reconstruct the composition logic from the XML; we supply the leaves.

This is what delivers breadth: a modest set of well-built leaf detectors lights up many high-value profiles.

## Layer 1 — Leaf detector catalogue (we author each pattern + validator)

✅ = deterministic validator (very low FP). ⚠️ = context-heavy / higher FP, best-effort.

### Group A — Financial (→ profiles: PCI, Financial)
| Detector | Validator | Notes |
|---|---|---|
| Credit / debit card | ✅ Luhn | 13–19 digit major networks |
| IBAN | ✅ mod-97 | country code + length table |
| ABA routing number | ✅ checksum | 9-digit weighted mod-10 |
| SWIFT / BIC | format | 8 or 11 alnum |
| Bank account (generic) | ⚠️ none | high FP — needs keyword context |

### Group B — Core identity / PII (→ profiles: PII, HIPAA)
| Detector | Validator | Notes |
|---|---|---|
| Email address | format | pragmatic RFC subset |
| IP address (v4/v6) | format | also a HIPAA identifier |
| Phone number (NA + intl) | format | |
| Date of birth / date | ⚠️ format | context word ("DOB", "born") to cut FP |
| Postal / mailing address | ⚠️ heuristic | structure + street/zip tokens |
| Person name | ⚠️ dictionary | hard for regex — dictionary/NER, best-effort or defer |
| URL | format | HIPAA identifier |
| Vehicle ID (VIN) / plate | ✅ VIN checksum | HIPAA identifier |

### Group C — Government / national IDs (US + UK focus)
| Detector | Validator | Notes |
|---|---|---|
| US SSN / Taxpayer ID | range rules | needs range-guard rewrite (no lookahead in RE2) |
| US EIN | prefix table | |
| US passport | format | |
| US driver's licence | ⚠️ per-state | fragmented; best-effort subset |
| UK NINO | format | |
| UK passport / UTR | format | |

### Group D — Health / PHI (→ profile: HIPAA)
| Detector | Validator | Notes |
|---|---|---|
| Medical record number (MRN) | ⚠️ context | format + keyword |
| US NPI | ✅ Luhn-based | |
| US DEA number | ✅ checksum | |
| ICD-10 diagnosis code | format | `[A-TV-Z]\d{2}(\.\d{1,4})?` |
| Health insurance number (generic) | format | |

### Group E — Technical secrets (→ profile: Secrets)
| Detector | Validator | Notes |
|---|---|---|
| API / cloud keys (AWS etc.) | prefix + entropy | high security value |
| Private keys (PEM) | marker | `-----BEGIN … PRIVATE KEY-----` |
| JWT / bearer token | structure | three base64url segments |

## Layer 2 — Profiles (named concepts, composed from detectors)

Reconstructed from the XML composition semantics; thresholds tunable.

| Profile | Composition (illustrative) | Source bucket |
|---|---|---|
| **PCI** | credit card (Luhn-valid) ≥1 | Financial_PCI |
| **Financial** | card OR IBAN OR ABA OR SWIFT OR bank account | Financial_PCI |
| **PHI / HIPAA** | (≥1 of {MRN, NPI, DEA, ICD-10, health-insurance}) AND (≥2 of {name, DOB, SSN, address, phone, email}) | PHI_Medical |
| **US PII** | (≥2 distinct PII detectors) OR (≥1 of {SSN, passport, card}) | PII_Personal_Data |
| **Secrets** | any Group E detector ≥1 | Technical_Keys_Secrets |

> The XML defines these per-country/per-regulation; for MVP we implement a small, representative set of profiles and a representative leaf set, then expand.

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

## Decisions — LOCKED (2026-06-24)
- [x] Exclude detecting bundles/frameworks/keyword-concepts as monolithic patterns.
- [x] Adopt **two-layer model**: leaf detectors + composed profiles → this is how we get PII/HIPAA breadth.
- [x] Geographic focus = **US + UK + global**.
- [x] **MVP profiles = PCI, Financial, US PII, PHI/HIPAA** (Secrets profile = near-free bonus, leaves are built).
- [x] **Leaf set = broad (Groups A–E, ~25 detectors)** — enough to light up all four profiles.
- [x] **Context-heavy leaves (DOB, address, name) = best-effort now** with required context keywords + low confidence; name is weakest (minimal dictionary/title heuristic).

### Locked MVP leaf detectors
- **A Financial:** credit card (✅Luhn), IBAN (✅mod-97), ABA (✅checksum), SWIFT/BIC, bank account (⚠️context)
- **B Identity/PII:** email, IP v4/v6, phone (NA+intl), DOB (⚠️), postal address (⚠️), person name (⚠️), URL, VIN (✅checksum)
- **C Gov IDs (US+UK):** US SSN, US EIN, US passport, UK NINO, UK passport/UTR
- **D Health:** MRN (⚠️context), US NPI (✅Luhn), US DEA (✅checksum), ICD-10 code, health insurance #
- **E Secrets:** API/cloud keys, PEM private key, JWT

## Status update (2026-06-24)
Tier-2 shipped: added `us_itin`, `us_drivers_license`, `us_medicare_mbi`,
`uk_drivers_license`, and a **UK_PII** profile (which also activates the existing
UK NINO/passport/UTR detectors).

Canada + EU national IDs shipped: `canada_sin` (Luhn), `fr_nir` (mod-97),
`de_tax_id` (ISO 7064 MOD 11,10), `italy_codice_fiscale`, `es_dni` (mod-23),
`nl_bsn` (11-test), with new **CA_PII** and **EU_PII** profiles.

Standalone **EMAIL** and **IP_ADDRESS** profiles added (so a lone email/IP is
flagged; email→BLOCK, single IP→ESCALATE, multiple IPs→BLOCK).

Engine now has **37 detectors across 10 profiles** (PCI, Financial, US PII, UK PII,
CA PII, EU PII, PHI/HIPAA, Secrets, Email, IP).

## Next step
The supported list is built. Build the PoC: (1) author RE2 patterns + validators for the leaves into our own rules/profiles definition file; (2) implement the leaf scanner + profile composition engine; (3) synthetic corpus + latency benchmark vs budget (≤50 MB, ≤3% CPU, <100 ms for ≤500 KB).
