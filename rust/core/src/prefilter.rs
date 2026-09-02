//! Multi-literal presence matcher used to decide, in a single pass, which literal-anchored
//! detectors can possibly match a buffer (so the rest are skipped). This is the cheap
//! "multi-pattern matcher" front end to the regex detectors.
//!
//! `internal/prefilter` hand-rolled its own Aho-Corasick automaton in Go; here we use the
//! `aho-corasick` crate (same author as `regex`, which `rules`/`scan` will also depend on)
//! rather than reimplementing it. Semantics preserved: `present()` reports every pattern that
//! occurs *anywhere* in the text, including overlapping occurrences — not just non-overlapping
//! leftmost matches — matching the Go version's fail-link-merged output sets.

use aho_corasick::AhoCorasick;

#[derive(Debug)]
pub struct Matcher {
    ac: Option<AhoCorasick>,
    pattern_count: usize,
}

impl Matcher {
    /// Builds an automaton over the given literal patterns.
    pub fn new(patterns: &[String]) -> Matcher {
        let pattern_count = patterns.len();
        if pattern_count == 0 {
            return Matcher { ac: None, pattern_count };
        }
        let ac = AhoCorasick::new(patterns).expect("prefilter literals must build into an automaton");
        Matcher { ac: Some(ac), pattern_count }
    }

    /// Returns a bool per pattern index: true if that literal occurs in `text`. One
    /// `O(len(text))` pass for all patterns.
    pub fn present(&self, text: &str) -> Vec<bool> {
        let mut present = vec![false; self.pattern_count];
        if let Some(ac) = &self.ac {
            for m in ac.find_overlapping_iter(text) {
                present[m.pattern().as_usize()] = true;
            }
        }
        present
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_overlapping_example() {
        // The canonical Aho-Corasick worked example (Wikipedia): patterns "he"/"she"/"his"/
        // "hers" against "ushers" — "he", "she" and "hers" all occur (overlapping), "his" doesn't.
        let patterns: Vec<String> = ["he", "she", "his", "hers"].iter().map(|s| s.to_string()).collect();
        let m = Matcher::new(&patterns);
        assert_eq!(m.present("ushers"), vec![true, true, false, true]);
    }

    #[test]
    fn no_patterns_present() {
        let patterns: Vec<String> = ["zzz", "qqq"].iter().map(|s| s.to_string()).collect();
        let m = Matcher::new(&patterns);
        assert_eq!(m.present("nothing matches here"), vec![false, false]);
    }

    #[test]
    fn empty_pattern_list() {
        let m = Matcher::new(&[]);
        assert_eq!(m.present("anything"), Vec::<bool>::new());
    }
}
