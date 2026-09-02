//! Loads the local detection definition (`../../../config/rules.json`): leaf detectors (regex,
//! dictionary, or code) and profile compositions. Compiling a pattern with the `regex` crate IS
//! the RE2 / LOCAL_CAPABLE compatibility check (see the crate-level comment in Cargo.toml).
//!
//! Ported from `internal/rules/rules.go`.

use std::collections::{HashMap, HashSet};
use std::fmt;

use regex::Regex;
use serde::Deserialize;

use crate::prefilter;

/// Compatibility classes (spec §2.2).
pub const LOCAL_CAPABLE: &str = "LOCAL_CAPABLE";
pub const CLOUD_ONLY: &str = "CLOUD_ONLY";

#[derive(Debug)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error(format!("parse rules: {e}"))
    }
}

/// Short-circuits scanning once the endpoint already has a strong, reportable signal: stop
/// scanning further detectors once a high-confidence profile has matched, or once total matches
/// cross a saturation cap. This is a hot-path cost optimisation (spec resource budget), not a
/// policy action — the engine reports matches; enforcement decisions happen outside this crate.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct EarlyExit {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub stop_on_high_confidence: bool,
    #[serde(default)]
    pub max_total_matches: i64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ConfidenceModel {
    #[serde(default)]
    pub validator_boost: i64,
    #[serde(default)]
    pub keyword_boost: i64,
    #[serde(default)]
    pub instance_boost: i64,
    #[serde(default)]
    pub max_instance_boosts: i64,
    #[serde(default)]
    pub keyword_window: i64,
    #[serde(default)]
    pub default_fire_threshold: i64,
    #[serde(default)]
    pub high_confidence_threshold: i64,
    #[serde(default)]
    pub early_exit: EarlyExit,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Scoring {
    #[serde(default)]
    pub name_evidence_hit: i64,
    #[serde(default)]
    pub adjacency_bonus: i64,
    #[serde(default)]
    pub title_bonus: i64,
    #[serde(default)]
    pub keyword_bonus: i64,
    #[serde(default)]
    pub fire_threshold: i64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Dictionary {
    #[serde(default)]
    pub given_names: String,
    #[serde(default)]
    pub surnames: String,
    #[serde(default)]
    pub common_words: String,
    #[serde(default)]
    pub titles: Vec<String>,
    #[serde(default)]
    pub max_span_tokens: i64,
    #[serde(default)]
    pub keyword_window: i64,
    #[serde(default)]
    pub scoring: Scoring,

    // Loaded lexicon sets — not from JSON, filled in by `build`.
    #[serde(skip)]
    pub given: HashSet<String>,
    #[serde(skip)]
    pub surn: HashSet<String>,
    #[serde(skip)]
    pub high_freq: HashSet<String>,
    #[serde(skip)]
    pub title_set: HashSet<String>,
}

/// Weights the evidence families of the source-code classifier. All are tunable in
/// `rules.json` so calibration needs no recompile.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CodeScoring {
    #[serde(default)]
    pub keyword_weight: i64,
    #[serde(default)]
    pub operator_weight: i64,
    #[serde(default)]
    pub punct_weight: i64,
    #[serde(default)]
    pub indent_weight: i64,
    #[serde(default)]
    pub comment_weight: i64,
    #[serde(default)]
    pub prose_penalty: i64,
    #[serde(default)]
    pub min_keyword_hits: i64,
    #[serde(default)]
    pub min_lines: i64,
    #[serde(default)]
    pub fire_threshold: i64,
    #[serde(default)]
    pub base_confidence: i64,
}

/// Drives the language-agnostic source-code classifier (`kind: "code"`). A scoring detector
/// like the person-name dictionary, not regex+checksum: source code has no checksum, so
/// reliability comes from requiring several corroborating evidence families and penalising
/// prose. Token sets and weights live here; feature extraction lives in `crate::scan`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CodeModel {
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub operators: Vec<String>,
    #[serde(default)]
    pub comments: Vec<String>,
    #[serde(default)]
    pub scoring: CodeScoring,
}

/// A cheap pre-check: skip this detector's regex unless one of its literals is present
/// (Aho-Corasick) and/or the file contains a digit.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Prefilter {
    #[serde(default)]
    pub literals: Vec<String>,
    #[serde(default)]
    pub needs_digit: bool,
    // Indices into DB::lit_matcher — not from JSON, filled in by `build`.
    #[serde(skip)]
    pub lit_idx: Vec<usize>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Detector {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub group: String,
    /// "" => regex, "dictionary", or "code".
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub data_types: Vec<String>,
    #[serde(default, rename = "patterns")]
    pub pattern_strs: Vec<String>,
    #[serde(default)]
    pub validators: Vec<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub base_confidence: i64,
    #[serde(default)]
    pub best_effort: bool,
    #[serde(default, rename = "dictionary")]
    pub dict: Option<Dictionary>,
    #[serde(default)]
    pub code: Option<CodeModel>,
    #[serde(default)]
    pub prefilter: Option<Prefilter>,

    // Compiled — not from JSON, filled in by `build`.
    #[serde(skip)]
    pub patterns: Vec<Regex>,
    #[serde(skip)]
    pub combined: String,
    #[serde(skip)]
    pub compat: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Node {
    #[serde(default)]
    pub op: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub min: i64,
    #[serde(default)]
    pub min_count: i64,
    #[serde(default)]
    pub min_validated: i64,
    #[serde(default)]
    pub of: Vec<Node>,
}

/// A named concept (e.g. PCI, US_PII) composed from leaf detectors. Carries a `data_type` for
/// cloud comparability. Deliberately has no action field: the engine reports which profiles
/// matched and how strongly; the policy engine (outside this crate) decides what to do about it.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Profile {
    pub profile_id: String,
    #[serde(default)]
    pub profile_name: String,
    #[serde(default)]
    pub data_type: String,
    #[serde(default, rename = "match")]
    pub match_node: Node,
}

/// Matches sensitivity/classification labels (spec §4.5/§5): metadata property names and
/// visible label strings.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct LabelMarker {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub strings: Vec<String>,
    #[serde(default)]
    pub metadata_properties: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct DB {
    #[serde(default)]
    pub schema_version: String,
    #[serde(default, rename = "confidence_model")]
    pub conf: ConfidenceModel,
    #[serde(default)]
    pub detectors: Vec<Detector>,
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub label_markers: Vec<LabelMarker>,

    /// The single Aho-Corasick automaton over every detector's literal cues — one pass tells
    /// the scanner which detectors can match. Not from JSON, filled in by `build`.
    #[serde(skip)]
    pub lit_matcher: Option<prefilter::Matcher>,

    #[serde(skip)]
    by_id: HashMap<String, usize>,
}

impl DB {
    pub fn detector(&self, id: &str) -> Option<&Detector> {
        self.by_id.get(id).map(|&i| &self.detectors[i])
    }
}

/// Resolves a lexicon path to its bytes (disk in `load`, an in-memory map in `load_bytes` for
/// filesystem-free environments like browser WASM).
type Opener<'a> = dyn Fn(&str) -> Result<Vec<u8>, Error> + 'a;

/// Reads, parses, compiles patterns, and loads lexicons from disk.
///
/// Lexicon paths inside the rules file (e.g. `"config/lexicons/given_names.txt"`) are written
/// relative to the *repo root*, not to the rules file's own directory (`rules.json` itself
/// lives one level down, in `config/`) — so a single fixed base won't work. Rather than hard-
/// coding "go up exactly one level", probe a handful of plausible bases (the rules file's own
/// directory, its parent, and the process's current directory as a last-resort fallback
/// matching the Go original) and use the first one where the path actually exists. This means
/// `--rules /anywhere/rules.json` works no matter which directory the binary is invoked from,
/// rather than requiring the caller to `cd` to match wherever the lexicon paths were authored
/// against.
pub fn load(path: &str) -> Result<DB, Error> {
    let raw = std::fs::read(path)?;
    let rules_dir = std::path::Path::new(path).parent().unwrap_or_else(|| std::path::Path::new("."));
    let bases: Vec<std::path::PathBuf> = [
        Some(rules_dir.to_path_buf()),
        rules_dir.parent().map(std::path::Path::to_path_buf),
        Some(std::path::PathBuf::from(".")),
    ]
    .into_iter()
    .flatten()
    .collect();
    build(&raw, &move |p| {
        let candidate = bases
            .iter()
            .map(|base| base.join(p))
            .find(|c| c.exists())
            .unwrap_or_else(|| std::path::PathBuf::from(p));
        std::fs::read(&candidate).map_err(Error::from)
    })
}

/// Builds a DB from in-memory rules JSON and a map of lexicon path -> contents (keys must
/// match the dictionary paths in the rules file). For environments without a filesystem.
pub fn load_bytes(rules_json: &[u8], lexicons: &HashMap<String, Vec<u8>>) -> Result<DB, Error> {
    build(rules_json, &|p| {
        lexicons.get(p).cloned().ok_or_else(|| Error(format!("lexicon not provided: {p}")))
    })
}

fn build(raw: &[u8], open: &Opener) -> Result<DB, Error> {
    let mut db: DB = serde_json::from_slice(raw)?;

    let mut by_id = HashMap::with_capacity(db.detectors.len());
    for (i, d) in db.detectors.iter_mut().enumerate() {
        by_id.insert(d.id.clone(), i);
        d.compat = LOCAL_CAPABLE.to_string();

        // Classify each pattern individually (the RE2/LOCAL_CAPABLE check), then combine the
        // valid ones into a single alternation so the scanner makes one pass per detector
        // instead of one pass per pattern.
        let mut valid = Vec::new();
        for p in &d.pattern_strs {
            if Regex::new(p).is_ok() {
                valid.push(p.clone());
            } else {
                d.compat = CLOUD_ONLY.to_string(); // rejected (spec §2.2). Record, never crash.
            }
        }
        if !valid.is_empty() {
            let combined = format!("(?:{})", valid.join(")|(?:"));
            match Regex::new(&combined) {
                Ok(re) => {
                    d.combined = combined;
                    d.patterns = vec![re];
                }
                Err(_) => {
                    d.patterns = valid.iter().filter_map(|p| Regex::new(p).ok()).collect();
                }
            }
        }

        if d.kind == "dictionary"
            && let Some(dict) = d.dict.as_mut()
        {
            load_dict(dict, open)?;
        }
    }
    db.by_id = by_id;

    // Build one Aho-Corasick automaton across all detector literal cues.
    let mut lits: Vec<String> = Vec::new();
    for d in db.detectors.iter_mut() {
        let Some(pf) = d.prefilter.as_mut() else { continue };
        for lit in &pf.literals {
            pf.lit_idx.push(lits.len());
            lits.push(lit.clone());
        }
    }
    if !lits.is_empty() {
        db.lit_matcher = Some(prefilter::Matcher::new(&lits));
    }

    Ok(db)
}

fn load_dict(d: &mut Dictionary, open: &Opener) -> Result<(), Error> {
    d.given = load_set(open, &d.given_names)?;
    d.surn = load_set(open, &d.surnames)?;
    d.high_freq = load_set(open, &d.common_words)?;
    d.title_set = d.titles.iter().map(|t| t.to_lowercase()).collect();
    Ok(())
}

fn load_set(open: &Opener, path: &str) -> Result<HashSet<String>, Error> {
    let data = open(path).map_err(|e| Error(format!("lexicon {path}: {e}")))?;
    let text = String::from_utf8_lossy(&data);
    Ok(text
        .lines()
        .filter_map(|line| {
            let w = line.trim().to_lowercase();
            if w.is_empty() { None } else { Some(w) }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // Resolve against CARGO_MANIFEST_DIR rather than the process's current directory, so tests
    // don't depend on / mutate process CWD regardless of where `cargo test` is invoked from.
    fn repo_root() -> &'static Path {
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
    }

    fn load_real_db() -> DB {
        let root = repo_root();
        let raw = std::fs::read(root.join("config/rules.json")).expect("read config/rules.json");
        build(&raw, &|p| std::fs::read(root.join(p)).map_err(Error::from)).expect("real rules.json should build")
    }

    #[test]
    fn load_resolves_lexicons_relative_to_the_rules_file_not_cwd() {
        // Regression test: load() must work when invoked with an absolute (or otherwise
        // CWD-independent) path to rules.json, even though process CWD here is rust/core, not
        // the repo root — lexicon paths inside rules.json ("config/lexicons/...") must resolve
        // against the rules file's own directory, not wherever the binary happens to run from.
        let path = repo_root().join("config/rules.json");
        let db = load(path.to_str().unwrap()).expect("load() should resolve lexicons relative to the rules file, not CWD");
        let person = db.detector("person_name").expect("person_name detector present");
        let dict = person.dict.as_ref().expect("person_name has a dictionary block");
        assert!(!dict.given.is_empty(), "given-name lexicon should have loaded via the rules-file-relative path");
    }

    #[test]
    fn real_rules_file_is_fully_local_capable() {
        // Every pattern in config/rules.json is RE2-safe by construction (no lookaround/
        // backreferences — see DECISIONS.md, 2026-06-24 "Open: negative-lookahead PII
        // patterns"), so nothing should classify CLOUD_ONLY.
        let db = load_real_db();
        assert!(db.detectors.len() >= 38, "expected at least 38 detectors, got {}", db.detectors.len());
        let cloud_only: Vec<&str> = db.detectors.iter().filter(|d| d.compat == CLOUD_ONLY).map(|d| d.id.as_str()).collect();
        assert!(cloud_only.is_empty(), "unexpected CLOUD_ONLY detectors: {cloud_only:?}");
    }

    #[test]
    fn dictionary_lexicons_load() {
        let db = load_real_db();
        let person = db.detector("person_name").expect("person_name detector present");
        let dict = person.dict.as_ref().expect("person_name has a dictionary block");
        assert!(!dict.given.is_empty(), "given-name lexicon should be non-empty");
        assert!(!dict.surn.is_empty(), "surname lexicon should be non-empty");
        assert!(!dict.high_freq.is_empty(), "common-words lexicon should be non-empty");
        assert!(dict.title_set.contains("dr"));
    }

    #[test]
    fn literal_prefilter_matcher_builds() {
        let db = load_real_db();
        assert!(db.lit_matcher.is_some(), "expected a literal prefilter matcher from detector literals");
        let credit_card = db.detector("credit_card").expect("credit_card detector present");
        assert!(credit_card.prefilter.as_ref().unwrap().needs_digit);
    }

    #[test]
    fn combined_pattern_compiles_for_multi_pattern_detector() {
        let db = load_real_db();
        let ip = db.detector("ip_address").expect("ip_address detector present");
        assert_eq!(ip.patterns.len(), 1, "multi-pattern detectors should combine into one alternation");
    }

    #[test]
    fn unknown_detector_lookup_is_none() {
        let db = load_real_db();
        assert!(db.detector("not_a_real_detector_id").is_none());
    }
}
