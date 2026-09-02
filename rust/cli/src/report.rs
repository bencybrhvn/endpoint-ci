//! `--report`: the rule compatibility report.

use ch_inspect_core::rules;

pub fn print_report(db: &rules::DB) {
    let cloud = db.detectors.iter().filter(|d| d.compat == rules::CLOUD_ONLY).count();
    let capable = db.detectors.len() - cloud;

    println!("Rule compilation report");
    println!("  Detectors:        {}", db.detectors.len());
    println!("  LOCAL_CAPABLE:    {capable}");
    println!("  CLOUD_ONLY:       {cloud}");
    println!("  Profiles:         {}\n", db.profiles.len());
    for d in &db.detectors {
        let kind = if d.kind.is_empty() { "regex" } else { d.kind.as_str() };
        println!(
            "  {:<16} {:<14} {:<8} patterns={} validators={:?}",
            d.id,
            d.compat,
            kind,
            d.pattern_strs.len(),
            d.validators
        );
    }
    if cloud > 0 {
        println!("\nCLOUD_ONLY (not evaluated locally):");
        for d in db.detectors.iter().filter(|d| d.compat == rules::CLOUD_ONLY) {
            println!("  - {}", d.id);
        }
    }
}
