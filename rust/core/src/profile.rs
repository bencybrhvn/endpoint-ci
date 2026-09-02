//! Evaluates profile composition trees (and/or/detector with min/min_count/min_validated) over
//! the leaf detector results. Ported from `internal/profile/profile.go`.

use std::collections::HashMap;

use crate::rules::{DB, Node};
use crate::scan::Result as ScanResult;

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Match {
    pub profile_id: String,
    pub profile_name: String,
    pub data_type: String,
    /// Representative confidence (0-100).
    pub confidence: i64,
    /// Contributing leaf detector (rule) IDs.
    pub rules: Vec<String>,
}

/// Returns the profiles that match the given detector results. Each match reports its
/// representative confidence and the leaf rule IDs that satisfied it — evidence for a
/// downstream policy engine, not an action.
pub fn evaluate(db: &DB, results: &HashMap<String, ScanResult>) -> Vec<Match> {
    let mut out = Vec::new();
    for p in &db.profiles {
        if eval(&p.match_node, results) {
            let mut rules = Vec::new();
            contributing(&p.match_node, results, &mut rules);
            out.push(Match {
                profile_id: p.profile_id.clone(),
                profile_name: p.profile_name.clone(),
                data_type: p.data_type.clone(),
                confidence: confidence(&p.match_node, results),
                rules,
            });
        }
    }
    out
}

/// Collects the leaf detector IDs that satisfied a matched tree: every child of an AND, only
/// the matched children of an OR.
fn contributing(n: &Node, res: &HashMap<String, ScanResult>, out: &mut Vec<String>) {
    match n.op.as_str() {
        "detector" => {
            if eval(n, res) {
                out.push(n.id.clone());
            }
        }
        "and" => {
            for ch in &n.of {
                contributing(ch, res, out);
            }
        }
        "or" => {
            for ch in &n.of {
                if eval(ch, res) {
                    contributing(ch, res, out);
                }
            }
        }
        _ => {}
    }
}

fn eval(n: &Node, res: &HashMap<String, ScanResult>) -> bool {
    match n.op.as_str() {
        "detector" => {
            let Some(r) = res.get(&n.id) else { return false };
            if !r.fired {
                return false;
            }
            if n.min_validated > 0 && r.validated_count < n.min_validated {
                return false;
            }
            if n.min_count > 0 && r.raw_count < n.min_count {
                return false;
            }
            true
        }
        "or" => {
            let min = if n.min == 0 { 1 } else { n.min };
            let matched = n.of.iter().filter(|ch| eval(ch, res)).count() as i64;
            matched >= min
        }
        "and" => n.of.iter().all(|ch| eval(ch, res)),
        _ => false,
    }
}

/// Representative score of a matched profile = the max confidence among contributing
/// (satisfied) detectors. Reported as the match strength.
fn confidence(n: &Node, res: &HashMap<String, ScanResult>) -> i64 {
    match n.op.as_str() {
        "detector" => res.get(&n.id).filter(|r| r.fired).map(|r| r.confidence).unwrap_or(0),
        "or" | "and" => n.of.iter().filter(|ch| eval(ch, res)).map(|ch| confidence(ch, res)).max().unwrap_or(0),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::load_real_db;

    fn fired(id: &str, confidence: i64, raw: i64, validated: i64) -> (String, ScanResult) {
        (
            id.to_string(),
            ScanResult {
                id: id.to_string(),
                raw_count: raw,
                validated_count: validated,
                confidence,
                fired: true,
                ..Default::default()
            },
        )
    }

    fn us_pii(db: &DB) -> &crate::rules::Profile {
        db.profiles
            .iter()
            .find(|p| p.profile_id == "US_PII")
            .expect("US_PII profile present in real rules.json")
    }

    #[test]
    fn two_weak_signals_satisfy_the_min_two_or_branch() {
        let db = load_real_db();
        let results: HashMap<_, _> = [fired("email", 80, 1, 1), fired("phone", 70, 1, 1)].into_iter().collect();
        let matches = evaluate(&db, &results);
        let m = matches
            .iter()
            .find(|m| m.profile_id == "US_PII")
            .expect("US_PII should fire on two weak signals");
        assert_eq!(m.confidence, 80);
        assert!(m.rules.contains(&"email".to_string()) && m.rules.contains(&"phone".to_string()));
    }

    #[test]
    fn a_single_weak_signal_does_not_satisfy_the_min_two_or_branch() {
        let db = load_real_db();
        let results: HashMap<_, _> = [fired("email", 80, 1, 1)].into_iter().collect();
        let matches = evaluate(&db, &results);
        assert!(
            matches.iter().all(|m| m.profile_id != "US_PII"),
            "lone email should not satisfy a min:2 OR branch"
        );
    }

    #[test]
    fn a_single_strong_validated_signal_fires_via_the_min_one_branch() {
        let db = load_real_db();
        let results: HashMap<_, _> = [fired("us_ssn", 90, 1, 1)].into_iter().collect();
        let matches = evaluate(&db, &results);
        let m = matches
            .iter()
            .find(|m| m.profile_id == "US_PII")
            .expect("validated us_ssn alone should fire US_PII");
        assert_eq!(m.rules, vec!["us_ssn".to_string()]);
    }

    #[test]
    fn min_validated_gate_blocks_an_unvalidated_hit() {
        let db = load_real_db();
        // us_ssn requires min_validated: 1 in the profile tree; fired but validated_count=0
        // must not satisfy that detector node even though the detector itself fired.
        let results: HashMap<_, _> = [fired("us_ssn", 90, 1, 0)].into_iter().collect();
        let matches = evaluate(&db, &results);
        assert!(matches.iter().all(|m| m.profile_id != "US_PII"));
    }

    #[test]
    fn confidence_is_the_max_among_contributing_detectors() {
        let db = load_real_db();
        let results: HashMap<_, _> = [fired("email", 60, 1, 1), fired("phone", 95, 1, 1)].into_iter().collect();
        let m = evaluate(&db, &results).into_iter().find(|m| m.profile_id == "US_PII").unwrap();
        assert_eq!(m.confidence, 95);
    }

    #[test]
    fn no_results_at_all_matches_nothing() {
        let db = load_real_db();
        assert!(evaluate(&db, &HashMap::new()).is_empty());
    }

    #[test]
    fn us_pii_tree_shape_sanity() {
        // Guards against a rules.json restructure silently invalidating the tests above.
        let db = load_real_db();
        let root = us_pii(&db);
        assert_eq!(root.match_node.op, "or");
        assert_eq!(root.match_node.of.len(), 2);
    }
}
