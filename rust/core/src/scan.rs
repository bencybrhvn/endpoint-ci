//! Runs the leaf detectors over a text buffer and produces a per-detector result with a
//! confidence score and a "fired" flag. Ported from `internal/scan/scan.go`.

use std::collections::HashMap;

use rayon::prelude::*;

use crate::rules::{DB, Detector};
use crate::util::{ceil_char_boundary, floor_char_boundary};
use crate::validators;

/// Bounds matches per detector. Far above any profile `min_count` or the instance-boost
/// ceiling (3), so it never changes verdicts in practice.
const MATCH_CAP: usize = 64;

#[derive(Debug, Clone, Default)]
pub struct Result {
    pub id: String,
    pub name: String,
    pub raw_count: i64,
    pub validated_count: i64,
    pub keyword_found: bool,
    pub confidence: i64,
    pub fired: bool,
    pub samples: Vec<String>,
}

/// Holds the once-per-buffer work (lowercasing + the single multi-pattern prefilter pass) so
/// the engine can scan detector subsets without redoing it.
pub struct Ctx {
    text: String,
    lower: String,
    lit_present: Option<Vec<bool>>,
    has_digit: bool,
}

impl Ctx {
    /// Runs the one-pass prefilter (Aho-Corasick literals + digit presence).
    pub fn new(text: &str, db: &DB) -> Ctx {
        let lower = text.to_lowercase();
        let lit_present = db.lit_matcher.as_ref().map(|m| m.present(text));
        let has_digit = text.bytes().any(|b| b.is_ascii_digit());
        Ctx {
            text: text.to_string(),
            lower,
            lit_present,
            has_digit,
        }
    }

    /// Scans the given detectors over the buffer, in parallel across cores (detectors are
    /// independent and read-only). Prefilter-skipped detectors are dropped cheaply. Matches may
    /// overlap across detectors, so each scans separately — a single combined alternation would
    /// let them steal each other's matches.
    pub fn scan_detectors(&self, db: &DB, dets: &[&Detector]) -> HashMap<String, Result> {
        dets.par_iter()
            .filter(|d| {
                // dictionary/code are whole-text scorers, not literal-anchored — never skip them.
                d.kind == "dictionary" || d.kind == "code" || !skip_by_prefilter(d, self.lit_present.as_deref(), self.has_digit)
            })
            .filter_map(|d| {
                let r = match d.kind.as_str() {
                    "dictionary" => scan_dictionary(&self.text, d, db),
                    "code" => scan_code(&self.text, d),
                    _ => scan_regex(&self.text, &self.lower, d, db),
                };
                r.map(|r| (d.id.clone(), r))
            })
            .collect()
    }
}

/// Evaluates every detector (convenience: one batch, no early exit).
pub fn scan(text: &str, db: &DB) -> HashMap<String, Result> {
    let ctx = Ctx::new(text, db);
    let dets: Vec<&Detector> = db.detectors.iter().collect();
    ctx.scan_detectors(db, &dets)
}

/// Reports whether a detector can be skipped without running its regex: a literal-anchored
/// detector with none of its literals present, or a needs-digit detector in a buffer with no
/// digits.
fn skip_by_prefilter(d: &Detector, lit_present: Option<&[bool]>, has_digit: bool) -> bool {
    let Some(pf) = &d.prefilter else { return false };
    if !pf.lit_idx.is_empty() {
        let any = pf.lit_idx.iter().any(|&ix| lit_present.map(|lp| lp[ix]).unwrap_or(false));
        if !any {
            return true;
        }
    }
    if pf.needs_digit && !has_digit {
        return true;
    }
    false
}

fn scan_regex(text: &str, lower: &str, d: &Detector, db: &DB) -> Option<Result> {
    // Context-gated (best-effort) detectors can't fire without a keyword anywhere in the file —
    // skip the regex pass entirely if none is present.
    if d.best_effort && !contains_any_keyword(lower, &d.keywords) {
        return None;
    }
    let mut strs = Vec::new();
    let mut positions = Vec::new();
    for re in &d.patterns {
        // Cap matches: we never need more than a handful to satisfy confidence boosts and
        // profile thresholds, and stopping the iterator early bounds cost on match-dense files.
        for m in re.find_iter(text).take(MATCH_CAP) {
            strs.push(m.as_str().to_string());
            positions.push(m.start());
        }
    }
    compute_regex_result(d, &strs, &positions, lower, db)
}

/// Turns collected matches into a scored detector result.
fn compute_regex_result(d: &Detector, strs: &[String], positions: &[usize], lower: &str, db: &DB) -> Option<Result> {
    if d.best_effort && !contains_any_keyword(lower, &d.keywords) {
        return None;
    }
    if strs.is_empty() {
        return None;
    }

    let has_validators = !d.validators.is_empty();
    let mut validated = 0i64;
    if has_validators {
        for s in strs {
            if d.validators.iter().all(|v| validators::run(v, s)) {
                validated += 1;
            }
        }
    }

    let kw = keyword_near(lower, positions, &d.keywords, db.conf.keyword_window as usize);

    let mut conf = d.base_confidence;
    if has_validators && validated > 0 {
        conf += db.conf.validator_boost;
    }
    if kw {
        conf += db.conf.keyword_boost;
    }
    let extra = (strs.len() as i64 - 1).min(db.conf.max_instance_boosts);
    conf += extra * db.conf.instance_boost;
    conf = conf.min(100);

    let mut fired = conf >= db.conf.default_fire_threshold;
    if has_validators && validated == 0 {
        // Validator exists but nothing validated => suppress.
        fired = false;
    }
    if d.best_effort && !kw {
        // Context-gated detectors need a nearby keyword.
        fired = false;
    }

    let validated_count = if has_validators { validated } else { strs.len() as i64 };

    Some(Result {
        id: d.id.clone(),
        name: d.name.clone(),
        raw_count: strs.len() as i64,
        validated_count,
        keyword_found: kw,
        confidence: conf,
        fired,
        samples: strs.iter().take(3).cloned().collect(),
    })
}

fn contains_any_keyword(lower: &str, keywords: &[String]) -> bool {
    keywords.iter().any(|k| lower.contains(&k.to_lowercase()))
}

fn keyword_near(lower: &str, positions: &[usize], keywords: &[String], window: usize) -> bool {
    if keywords.is_empty() {
        return false;
    }
    // Precompute once per call rather than re-lowering inside the position loop (Go re-lowers
    // per keyword per position; a faithful but wasteful pattern not worth reproducing).
    let keywords_lower: Vec<String> = keywords.iter().map(|k| k.to_lowercase()).collect();
    for &p in positions {
        // `p` is a byte offset into `text` (from the regex match), reused here to slice `lower`
        // — the same assumption Go's byte-string indexing makes (case-folding rarely changes
        // UTF-8 byte length). Unlike Go, Rust's `str` can't be sliced off a character boundary,
        // so clamp rather than panic on the rare codepoint where it does.
        let lo = floor_char_boundary(lower, p.saturating_sub(window));
        let hi = ceil_char_boundary(lower, (p + window).min(lower.len()));
        let seg = &lower[lo..hi];
        if keywords_lower.iter().any(|k| seg.contains(k.as_str())) {
            return true;
        }
    }
    false
}

// --- dictionary (person name) detector ---

struct Tok {
    start: usize,
    end: usize,
    cap: bool,
}

/// Runs the gazetteer person-name detector. Lowercases only capitalised tokens (the only
/// candidates), keeping the hot path cheap.
fn scan_dictionary(text: &str, d: &Detector, db: &DB) -> Option<Result> {
    let dc = d.dict.as_ref()?;
    let toks = tokenize(text);
    let low = |t: &Tok| text[t.start..t.end].to_lowercase();
    let name_evidence = |lw: &str| (dc.given.contains(lw) || dc.surn.contains(lw)) && !dc.high_freq.contains(lw);
    let lower = text.to_lowercase();
    let max_span = if dc.max_span_tokens == 0 { 3 } else { dc.max_span_tokens as usize };

    let mut fired = 0i64;
    let mut best = 0i64;
    let mut samples = Vec::new();

    let mut i = 0usize;
    while i < toks.len() {
        if !toks[i].cap {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < toks.len() && toks[j].cap && spaces_only(text, &toks[j - 1], &toks[j]) {
            j += 1;
        }
        let run = &toks[i..j];
        let mut has_title = i > 0 && dc.title_set.contains(&low(&toks[i - 1])) && spaces_only(text, &toks[i - 1], &toks[i]);
        let mut start = 0;
        if dc.title_set.contains(&low(&run[0])) {
            has_title = true;
            start = 1;
        }
        let mut span = &run[start..];
        if span.len() > max_span {
            span = &span[..max_span];
        }
        if !span.is_empty() {
            let mut score = 0i64;
            let mut name_toks = 0;
            for t in span {
                if name_evidence(&low(t)) {
                    score += dc.scoring.name_evidence_hit;
                    name_toks += 1;
                }
            }
            if name_toks >= 2 {
                score += dc.scoring.adjacency_bonus;
            }
            if has_title {
                score += dc.scoring.title_bonus;
            }
            if keyword_near(&lower, &[span[0].start], &d.keywords, db.conf.keyword_window as usize) {
                score += dc.scoring.keyword_bonus;
            }
            let conf = (40 + score * 8).min(95);
            if score >= dc.scoring.fire_threshold {
                fired += 1;
                if conf > best {
                    best = conf;
                }
                if samples.len() < 3 {
                    let parts: Vec<&str> = span.iter().map(|t| &text[t.start..t.end]).collect();
                    samples.push(parts.join(" "));
                }
            }
        }
        i = j;
    }
    if fired == 0 {
        return None;
    }
    Some(Result {
        id: d.id.clone(),
        name: d.name.clone(),
        raw_count: fired,
        validated_count: fired,
        keyword_found: false,
        confidence: best,
        fired: true,
        samples,
    })
}

/// Splits text into word tokens (single pass, no per-rune allocation).
fn tokenize(text: &str) -> Vec<Tok> {
    let mut toks = Vec::with_capacity(text.len() / 6);
    let mut i = 0;
    while i < text.len() {
        let ch = text[i..].chars().next().expect("i < text.len() implies a next char");
        if !ch.is_alphabetic() {
            i += ch.len_utf8();
            continue;
        }
        let start = i;
        let capit = ch.is_uppercase();
        i += ch.len_utf8();
        while i < text.len() {
            let next = text[i..].chars().next().expect("i < text.len() implies a next char");
            if next.is_alphabetic() || next == '\'' || next == '-' {
                i += next.len_utf8();
            } else {
                break;
            }
        }
        toks.push(Tok { start, end: i, cap: capit });
    }
    toks
}

fn spaces_only(text: &str, a: &Tok, b: &Tok) -> bool {
    if b.start < a.end {
        return false;
    }
    text[a.end..b.start].chars().all(|c| c == ' ' || c == '\t')
}

// --- source-code classifier (kind "code") ---

/// The language-agnostic source-code classifier. Source code carries no checksum, so — like
/// the person-name scorer — reliability comes from combining several corroborating evidence
/// families (keyword/operator density, structural punctuation, indentation, comments),
/// penalising natural-language prose, and requiring a minimum keyword presence before it can
/// fire (which is what keeps JSON/YAML/prose/logs from tripping it). One O(n) pass over lines
/// plus a token-count pass; weights and token sets come from `rules.json`.
fn scan_code(text: &str, d: &Detector) -> Option<Result> {
    let cm = d.code.as_ref()?;
    let sc = &cm.scoring;

    // Occurrence counts. Case-sensitive on purpose: real code keywords are lower-case tokens
    // ("func ", "def ") so sentence-case prose won't match.
    let kw_hits: i64 = cm.keywords.iter().map(|k| text.matches(k.as_str()).count() as i64).sum();
    let op_hits: i64 = cm.operators.iter().map(|o| text.matches(o.as_str()).count() as i64).sum();

    // Per-line structure in one pass: non-empty line count, indented lines, structural
    // punctuation, comment lines, and natural-language prose lines. Comment lines (licence
    // headers, doc comments) are positive evidence of code — NOT prose — so real source with a
    // big English licence block (very common) isn't penalised into silence.
    let mut lines = 0i64;
    let mut indent = 0i64;
    let mut prose = 0i64;
    let mut punct = 0i64;
    let mut comment = 0i64;
    let mut total_words = 0i64;

    let mut scan_line = |ln: &str| {
        let trimmed = ln.trim_start_matches([' ', '\t']);
        if trimmed.is_empty() {
            return;
        }
        lines += 1;
        if ln.len() > trimmed.len() {
            indent += 1;
        }
        if is_comment_line(trimmed) {
            comment += 1;
            return; // comments never count as prose
        }
        let mut words = 0i64;
        let mut in_word = false;
        let mut symbols = 0i64;
        for b in ln.bytes() {
            match b {
                b'{' | b'}' | b'(' | b')' | b'[' | b']' | b';' => {
                    punct += 1;
                    symbols += 1;
                }
                b'=' | b'<' | b'>' => symbols += 1,
                _ => {}
            }
            if is_word_byte(b) {
                if !in_word {
                    words += 1;
                    in_word = true;
                }
            } else {
                in_word = false;
            }
        }
        // A prose line: a long run of words carrying almost no code symbols. Symbol density
        // (not a terminal full stop) is the discriminator — it survives the truncated/
        // heading-heavy lines that document extraction produces, and legal outline numbering
        // "(a)(i)" can't disguise a sentence as code.
        if words >= 10 && symbols <= 2 {
            prose += 1;
        }
        total_words += words;
    };

    let mut start = 0;
    for (i, b) in text.bytes().enumerate() {
        if b == b'\n' {
            scan_line(&text[start..i]);
            start = i + 1;
        }
    }
    scan_line(&text[start..]);

    // Gates: too small to judge, or not enough keyword evidence to be code.
    if lines < sc.min_lines || kw_hits < sc.min_keyword_hits {
        return None;
    }

    // Normalise by an estimated logical-line count, not raw lines. Document extraction (docx/
    // pdf) concatenates paragraphs into a few very long lines, which would otherwise explode
    // the per-line keyword density and make prose look like dense code. ~12 words ≈ one
    // logical line of source.
    let fl = (lines as f64).max(total_words as f64 / 12.0);
    let clamp = |v: f64, hi: f64| v.min(hi);

    let score = sc.keyword_weight as f64 * clamp(kw_hits as f64 / fl, 2.0)
        + sc.operator_weight as f64 * clamp(op_hits as f64 / fl, 2.0)
        + sc.comment_weight as f64 * (comment as f64 / fl)
        + sc.indent_weight as f64 * (indent as f64 / fl)
        + sc.punct_weight as f64 * clamp((punct as f64 / fl) / 3.0, 1.0)
        - sc.prose_penalty as f64 * (prose as f64 / fl);

    if (score as i64) < sc.fire_threshold {
        return None;
    }
    let conf = (sc.base_confidence + score as i64).clamp(0, 95);

    Some(Result {
        id: d.id.clone(),
        name: d.name.clone(),
        raw_count: kw_hits,
        validated_count: kw_hits,
        keyword_found: false,
        confidence: conf,
        fired: true,
        samples: Vec::new(),
    })
}

fn is_word_byte(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
}

/// Reports whether a non-empty, whitespace-trimmed line begins with a line/block comment
/// marker common across languages (C/Java/JS `//`, `/*` and `*` continuations; shell/Python/
/// Ruby `#`; SQL/Lua `--`; Fortran `!`; INI/asm `;`; SGML `<!--`; Python/Ruby docstring
/// delimiters). Comment prose is code, not prose.
fn is_comment_line(trimmed: &str) -> bool {
    match trimmed.as_bytes()[0] {
        b'#' | b'*' | b'!' | b';' => return true,
        _ => {}
    }
    const PREFIXES: &[&str] = &["//", "/*", "--", "<!--", "\"\"\"", "'''"];
    PREFIXES.iter().any(|p| trimmed.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{load_real_db, repo_root};

    #[test]
    fn credit_card_fires_with_luhn_valid_number() {
        let db = load_real_db();
        let text = "Please charge card 4111111111111111 for the order, thanks.";
        let results = scan(text, &db);
        let r = results.get("credit_card").expect("credit_card should have a result");
        assert!(r.fired, "expected credit_card to fire: {r:?}");
        assert_eq!(r.validated_count, 1);
    }

    #[test]
    fn credit_card_does_not_fire_on_luhn_invalid_number() {
        let db = load_real_db();
        // Same shape, last digit flipped so Luhn fails; no validated matches => suppressed.
        let text = "Please charge card 4111111111111112 for the order, thanks.";
        let results = scan(text, &db);
        if let Some(r) = results.get("credit_card") {
            assert!(!r.fired, "expected credit_card not to fire on Luhn-invalid number: {r:?}");
        }
    }

    #[test]
    fn clean_prose_does_not_fire_source_code() {
        let db = load_real_db();
        let text = "This is an ordinary paragraph of English prose. It has no code in it \
                     whatsoever, just sentences describing something in plain language for \
                     a good long while so the line-structure gates don't trivially reject it.";
        let results = scan(text, &db);
        assert!(results.get("source_code").is_none_or(|r| !r.fired));
    }

    #[test]
    fn go_source_fires_source_code() {
        let db = load_real_db();
        let text = std::fs::read_to_string(repo_root().join("testdata/corpus/code_go.txt")).unwrap();
        let results = scan(&text, &db);
        let r = results.get("source_code").expect("source_code should have a result");
        assert!(r.fired, "expected source_code to fire on real Go source: {r:?}");
    }

    #[test]
    fn prefilter_skips_detector_with_absent_literal_and_needs_digit() {
        let db = load_real_db();
        // credit_card's prefilter needs_digit=true; text has no digits at all, so it should be
        // skipped entirely (no result), not merely fail to fire.
        let text = "no digits anywhere in this sentence at all";
        let results = scan(text, &db);
        assert!(!results.contains_key("credit_card"));
    }
}
