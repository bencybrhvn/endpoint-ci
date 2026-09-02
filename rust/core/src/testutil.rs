//! Test-only helper for loading the real `rules.json` + lexicons, shared across module test
//! suites that need a fully-built `DB` rather than a hand-rolled one. `rules.rs`'s own tests
//! build via its private `build()` directly (they're testing the loader itself); everything
//! downstream (`scan`, `profile`, `engine`) just needs a working `DB` to test against.
#![cfg(test)]

use std::collections::HashMap;
use std::path::Path;

use crate::rules::DB;

pub(crate) fn repo_root() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

pub(crate) fn load_real_db() -> DB {
    let root = repo_root();
    let raw = std::fs::read(root.join("config/rules.json")).expect("read config/rules.json");
    let mut lexicons = HashMap::new();
    for name in ["given_names.txt", "surnames.txt", "common_words.txt"] {
        let p = format!("config/lexicons/{name}");
        lexicons.insert(p.clone(), std::fs::read(root.join(&p)).unwrap());
    }
    crate::rules::load_bytes(&raw, &lexicons).expect("real rules.json should build")
}
