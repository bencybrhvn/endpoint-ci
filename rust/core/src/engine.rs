//! Orchestrates the inspection pipeline and builds a match report.
//!
//! This component INSPECTS and REPORTS only. It never decides an action (block/allow/
//! quarantine): those are policy decisions made outside this crate. The report says what was
//! found — which profiles/data-types matched, how strongly, the contributing rules, sensitivity
//! labels, and neutral facts about the scan (coverage, readability) — and a downstream policy
//! engine decides what to do about it. Ported from `internal/engine/engine.go`.

use std::collections::HashMap;
use std::time::Instant;

use crate::extract::{self, Config as ExtractConfig};
use crate::format::Type;
use crate::label::{self, Match as LabelMatch};
use crate::profile::{self, Match as ProfileMatch};
use crate::rules::{DB, Detector};
use crate::scan::{self, Ctx};

/// Describes how much of the content was inspected — a neutral fact for the policy layer, not
/// an action.
pub const COVERAGE_FULL: &str = "full";
/// Size gate: only head/tail windows inspected.
pub const COVERAGE_PARTIAL: &str = "partial";
/// Extracted text hit the `max_bytes` cap.
pub const COVERAGE_TRUNCATED: &str = "truncated";

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DetectorFinding {
    /// rule_id (passes through unmodified).
    pub id: String,
    pub name: String,
    /// dataset_id(s) (pass through unmodified).
    pub data_types: Vec<String>,
    pub raw_count: i64,
    pub validated_count: i64,
    pub confidence: i64,
}

/// The output of inspecting one file: the matches found and neutral facts about the scan. It
/// carries no verdict/action.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Report {
    pub file: String,
    /// Always "local".
    pub scan_path: String,
    pub file_type: String,
    pub bytes_seen: i64,
    /// false: encrypted/corrupt/binary — no body inspected.
    pub readable: bool,
    /// full | partial | truncated.
    pub coverage: String,
    #[serde(default)]
    pub short_circuited: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(rename = "scan_duration_us")]
    pub scan_micros: i64,
    pub profiles: Vec<ProfileMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<LabelMatch>,
    pub detectors: Vec<DetectorFinding>,
}

impl Report {
    /// Reports whether any profile matched — a convenience for callers, not a policy signal.
    pub fn matched(&self) -> bool {
        !self.profiles.is_empty()
    }

    /// Reports whether any matched profile reached the given reporting-quality threshold. Used
    /// for summaries and early-exit; the policy engine may apply its own thresholds on top of
    /// the raw confidence scores.
    pub fn high_confidence(&self, threshold: i64) -> bool {
        self.profiles.iter().any(|m| m.confidence >= threshold)
    }
}

/// Sorts detectors so the strongest, most decisive ones run first (validator-backed and high
/// base confidence), best-effort last. This makes the early-exit fire after the first batch on
/// most match-dense files.
fn order_by_priority<'a>(dets: &[&'a Detector]) -> Vec<&'a Detector> {
    let score = |d: &Detector| -> i64 {
        let mut s = d.base_confidence;
        if !d.validators.is_empty() {
            s += 20;
        }
        if d.best_effort {
            s -= 100;
        }
        s
    };
    let mut out = dets.to_vec();
    out.sort_by_key(|d| std::cmp::Reverse(score(d))); // stable, descending
    out
}

fn has_high_confidence(matches: &[ProfileMatch], threshold: i64) -> bool {
    matches.iter().any(|m| m.confidence >= threshold)
}

/// Reads a file, detects its format, extracts text, then inspects.
pub fn inspect_file(path: &str, db: &DB, cfg: ExtractConfig) -> std::io::Result<Report> {
    let data = std::fs::read(path)?;
    Ok(inspect_data(path, &data, db, cfg))
}

/// Inspects an in-memory file: detect -> extract -> label -> scan -> report. No filesystem
/// access, so it works in browser/WASM (where bytes come from JS) as well as on the endpoint.
pub fn inspect_data(name: &str, data: &[u8], db: &DB, cfg: ExtractConfig) -> Report {
    let res = extract::extract(data, cfg);

    // Sensitivity-label fast-path (OOXML docProps / PDF XMP) runs on the raw bytes regardless
    // of text extraction — a labelled-but-unparseable doc must still be reported. Metadata
    // labels are machine-written, so they carry source=metadata for the policy layer to weigh.
    let meta = label::metadata(data, res.format_type, &db.label_markers);

    // No body to scan: report readable=false plus whatever the metadata fast-path found.
    // Unsupported/binary vs encrypted/corrupt is distinguished only in the note — both are
    // simply "no body inspected" as far as the report is concerned.
    if let Some(err) = res.err {
        let mut r = Report {
            file: name.to_string(),
            scan_path: "local".to_string(),
            file_type: res.format_type.to_string(),
            bytes_seen: data.len() as i64,
            readable: false,
            coverage: COVERAGE_FULL.to_string(),
            labels: meta.clone(),
            note: Some(err),
            ..Default::default()
        };
        if res.format_type == Type::Unsupported {
            r.note = Some("unsupported/binary type — not content-inspected".to_string());
        }
        if !meta.is_empty() {
            r.note = Some("sensitivity label present in metadata (body not extractable)".to_string());
        }
        return r;
    }

    let mut r = inspect(name, &res.text, db);
    r.file_type = res.format_type.to_string();
    r.coverage = if res.partial {
        COVERAGE_PARTIAL.to_string()
    } else if res.truncated {
        COVERAGE_TRUNCATED.to_string()
    } else {
        COVERAGE_FULL.to_string()
    };

    if !meta.is_empty() {
        let mut combined = meta;
        combined.extend(r.labels);
        r.labels = combined;
        if r.note.is_none() {
            r.note = Some("sensitivity label present in document metadata".to_string());
        }
    }
    r
}

/// Runs detectors + profiles over text and builds a match report.
///
/// Detectors are evaluated in priority-ordered batches (strong, validator-backed first). After
/// each batch we re-evaluate profiles; once a high-confidence profile has matched (or matches
/// saturate) we short-circuit — a hot-path cost optimisation. This can trim the reported
/// profile set, so the flag is surfaced.
pub fn inspect(file: &str, text: &str, db: &DB) -> Report {
    let start = Instant::now();

    let ctx = Ctx::new(text, db);
    let all_dets: Vec<&Detector> = db.detectors.iter().collect();
    let ordered = order_by_priority(&all_dets);
    let mut results: HashMap<String, scan::Result> = HashMap::new();
    let mut matches: Vec<ProfileMatch> = Vec::new();
    let mut total_matches: i64 = 0;
    let mut shorted = false;

    let batch = std::thread::available_parallelism().map(std::num::NonZeroUsize::get).unwrap_or(1).max(1);
    let ee = &db.conf.early_exit;
    let mut i = 0;
    while i < ordered.len() {
        let end = (i + batch).min(ordered.len());
        for (id, rr) in ctx.scan_detectors(db, &ordered[i..end]) {
            total_matches += rr.raw_count;
            results.insert(id, rr);
        }
        matches = profile::evaluate(db, &results);
        if ee.enabled {
            if ee.stop_on_high_confidence && has_high_confidence(&matches, db.conf.high_confidence_threshold) {
                shorted = true;
                break;
            }
            if ee.max_total_matches > 0 && total_matches >= ee.max_total_matches {
                shorted = true;
                break;
            }
        }
        i = end;
    }
    let elapsed = start.elapsed();

    let mut r = Report {
        file: file.to_string(),
        scan_path: "local".to_string(),
        bytes_seen: text.len() as i64,
        readable: true,
        coverage: COVERAGE_FULL.to_string(),
        scan_micros: elapsed.as_micros() as i64,
        profiles: matches,
        short_circuited: shorted,
        ..Default::default()
    };
    if shorted {
        r.note = Some("short-circuited: strong signal found, remaining detectors skipped".to_string());
    }

    // Fired detectors, sorted by confidence desc then id asc, for stable reporting.
    let mut fired: Vec<&scan::Result> = results.values().filter(|res| res.fired).collect();
    fired.sort_by(|a, b| b.confidence.cmp(&a.confidence).then_with(|| a.id.cmp(&b.id)));
    for res in fired {
        let data_types = db.detector(&res.id).map(|d| d.data_types.clone()).unwrap_or_default();
        r.detectors.push(DetectorFinding {
            id: res.id.clone(),
            name: res.name.clone(),
            data_types,
            raw_count: res.raw_count,
            validated_count: res.validated_count,
            confidence: res.confidence,
        });
    }

    // Body-text sensitivity labels (distinctive markings) — reported, not actioned.
    let body_labels = label::body(text, &db.label_markers);
    if !body_labels.is_empty() {
        r.labels.extend(body_labels);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{load_real_db, repo_root};
    use std::collections::HashMap as Map;

    fn make_large(n: usize) -> String {
        let block = "Lorem ipsum dolor sit amet. Contact john.doe@example.com or (415) 555-2671. \
                      Card 4111111111111111. SSN 123-45-6789. NPI 1234567893. IBAN GB82WEST12345698765432.\n";
        let mut s = String::new();
        while s.len() < n {
            s.push_str(block);
        }
        s
    }

    /// Ported from internal/engine/engine_test.go TestCorpus. Early-exit disabled so the FULL
    /// profile set is reported (detection completeness); the short-circuit path is covered by
    /// early_exit_short_circuits below.
    #[test]
    fn corpus_matches_go_oracle_expectations() {
        let mut db = load_real_db();
        db.conf.early_exit.enabled = false;
        let root = repo_root();
        let raw = std::fs::read(root.join("testdata/corpus/expectations.json")).unwrap();
        let exp: Map<String, serde_json::Value> = serde_json::from_slice(&raw).unwrap();

        let mut failures = Vec::new();
        for (name, want) in &exp {
            let text = std::fs::read_to_string(root.join("testdata/corpus").join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"));
            let v = inspect(name, &text, &db);
            let have: Vec<&str> = v.profiles.iter().map(|p| p.profile_id.as_str()).collect();
            let want_profiles: Vec<String> = want["profiles"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect();

            if want_profiles.is_empty() && !v.profiles.is_empty() {
                failures.push(format!("{name}: expected no profiles, got {have:?}"));
            }
            for wp in &want_profiles {
                if !have.contains(&wp.as_str()) {
                    failures.push(format!("{name}: missing profile {wp} (got {have:?})"));
                }
            }
            if let Some(want_hc) = want.get("high_confidence").and_then(|v| v.as_bool()) {
                let hc = v.high_confidence(db.conf.high_confidence_threshold);
                if hc != want_hc {
                    failures.push(format!("{name}: high_confidence = {hc}, want {want_hc} (profiles {have:?})"));
                }
            }
        }
        assert!(failures.is_empty(), "{} corpus mismatches:\n{}", failures.len(), failures.join("\n"));
    }

    /// Ported from TestDocuments: exercises the extraction layer (OOXML, PDF, encrypted) end
    /// to end.
    #[test]
    fn documents_end_to_end() {
        let mut db = load_real_db();
        db.conf.early_exit.enabled = false;
        let root = repo_root();

        struct Case {
            file: &'static str,
            profile: &'static str,
            want_label: bool,
            want_readable: bool,
        }
        let cases = [
            Case {
                file: "hipaa.docx",
                profile: "PHI_HIPAA",
                want_label: false,
                want_readable: true,
            },
            Case {
                file: "clean.docx",
                profile: "",
                want_label: false,
                want_readable: true,
            },
            Case {
                file: "pci.xlsx",
                profile: "PCI",
                want_label: false,
                want_readable: true,
            },
            Case {
                file: "financial.pptx",
                profile: "FINANCIAL",
                want_label: false,
                want_readable: true,
            },
            Case {
                file: "pii.pdf",
                profile: "US_PII",
                want_label: false,
                want_readable: true,
            },
            Case {
                file: "legacy.doc",
                profile: "",
                want_label: false,
                want_readable: false,
            },
            Case {
                file: "labeled.docx",
                profile: "",
                want_label: true,
                want_readable: true,
            },
            Case {
                file: "footer_marked.docx",
                profile: "",
                want_label: true,
                want_readable: true,
            },
            // Go's ledongthuc/pdf fails to parse this fixture's text layer at all (readable=
            // false there); pdf-extract genuinely succeeds and returns real content ("Project
            // status update. Lorem ipsum...") — a real PDF-library capability difference, not
            // a port bug. Confirmed by inspecting extract::extract's output directly.
            Case {
                file: "labeled.pdf",
                profile: "",
                want_label: true,
                want_readable: true,
            },
        ];
        for c in cases {
            let path = root.join("testdata/docs").join(c.file);
            let v = inspect_file(path.to_str().unwrap(), &db, ExtractConfig::default()).unwrap_or_else(|e| panic!("{}: {e}", c.file));
            assert_eq!(v.readable, c.want_readable, "{}: readable", c.file);
            if !c.profile.is_empty() {
                assert!(
                    v.profiles.iter().any(|p| p.profile_id == c.profile),
                    "{}: missing profile {}",
                    c.file,
                    c.profile
                );
            }
            if c.want_label {
                assert!(!v.labels.is_empty(), "{}: expected a sensitivity label", c.file);
            }
        }
    }

    /// Ported from TestEarlyExit: a PII-saturated buffer produces a high-confidence match
    /// without scanning every detector, and the report is still correct.
    #[test]
    fn early_exit_short_circuits_on_saturated_buffer() {
        let mut db = load_real_db();
        assert!(db.conf.early_exit.enabled, "early-exit should be enabled by default in rules.json");
        let th = db.conf.high_confidence_threshold;
        let text = make_large(200 * 1024);

        let v = inspect("dense", &text, &db);
        assert!(v.high_confidence(th), "expected a high-confidence match on a saturated buffer");
        assert!(v.short_circuited, "expected short-circuit on a saturated buffer");

        db.conf.early_exit.enabled = false;
        let full = inspect("dense", &text, &db);
        assert!(full.high_confidence(th), "full-scan: expected a high-confidence match");
        assert!(
            full.profiles.len() >= v.profiles.len(),
            "full scan should report >= profiles than short-circuit ({} vs {})",
            full.profiles.len(),
            v.profiles.len()
        );
    }

    /// Ported from TestSizeGate: PII buried in the skipped middle is not matched but coverage
    /// is reported "partial"; PII in the tail window is caught. Exercised via inspect_data
    /// directly rather than temp files on disk — the gate logic lives in extract::extract,
    /// which inspect_file just wraps with a filesystem read.
    #[test]
    fn size_gate_hides_middle_but_catches_tail() {
        let db = load_real_db();
        let filler = "Lorem ipsum dolor sit amet consectetur. ".repeat(4000); // ~160 KB
        let cfg = ExtractConfig {
            max_file_bytes: Some(64 << 10),
            head_tail_window: Some(8 << 10),
            ..Default::default()
        };

        let mid_pii = format!("{filler} Card 4111111111111111. SSN 123-45-6789. {filler}");
        let v = inspect_data("mid.txt", mid_pii.as_bytes(), &db, cfg);
        assert_eq!(v.coverage, COVERAGE_PARTIAL, "mid.txt coverage");
        assert!(
            !v.matched(),
            "mid.txt: expected no matches (middle PII not seen), got {} profiles",
            v.profiles.len()
        );

        let tail_pii = format!("{filler}{filler} payment card 4111111111111111 on file.\n");
        let v2 = inspect_data("tail.txt", tail_pii.as_bytes(), &db, cfg);
        assert_eq!(v2.coverage, COVERAGE_PARTIAL, "tail.txt coverage");
        assert!(v2.matched(), "tail.txt: expected a match (tail PII seen), got none");
    }

    /// Ported from TestSourceCode: fires on real code, stays silent on confusables (config/
    /// prose) that naive detectors trip on.
    #[test]
    fn source_code_classifier_end_to_end() {
        let mut db = load_real_db();
        db.conf.early_exit.enabled = false;
        let fires = |text: &str| inspect("x", text, &db).profiles.iter().any(|p| p.profile_id == "SOURCE_CODE");

        let go_src = "package store\n\nimport (\n\t\"errors\"\n\t\"sync\"\n)\n\n\
                       // Cache is a tiny concurrency-safe key/value store.\n\
                       type Cache struct {\n\tmu sync.Mutex\n\tm  map[string]int\n}\n\n\
                       func New() *Cache {\n\treturn &Cache{m: make(map[string]int)}\n}\n\n\
                       func (c *Cache) Get(k string) (int, error) {\n\tc.mu.Lock()\n\tdefer c.mu.Unlock()\n\
                       \tv, ok := c.m[k]\n\tif !ok {\n\t\treturn 0, errors.New(\"missing\")\n\t}\n\treturn v, nil\n}\n\n\
                       func (c *Cache) Set(k string, v int) {\n\tc.mu.Lock()\n\tc.m[k] = v\n\tc.mu.Unlock()\n}\n";
        assert!(fires(go_src), "expected SOURCE_CODE to fire on a Go snippet");

        let json_blob = "{\n  \"name\": \"svc\",\n  \"port\": 8080,\n  \"tags\": [\"a\", \"b\"],\n  \"nested\": {\"on\": true}\n}\n";
        assert!(!fires(json_blob), "SOURCE_CODE should not fire on a JSON config blob");

        let prose = "The quarterly report summarises our progress and outlines the plan. ".repeat(12);
        assert!(!fires(&prose), "SOURCE_CODE should not fire on natural-language prose");
    }
}
