// Command validate-rules loads a local rules.json and checks it:
//  1. JSON parses
//  2. every detector pattern compiles under Go's regexp (RE2) — our LOCAL_CAPABLE test
//  3. every profile detector reference resolves to a defined detector
//
// Usage: go run ./tools/validate-rules config/rules.json
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

type Detector struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Group      string   `json:"group"`
	Kind       string   `json:"kind"` // "" (regex, default) or "dictionary"
	Patterns   []string `json:"patterns"`
	Validators []string `json:"validators"`
	Dictionary *struct {
		GivenNames  string `json:"given_names"`
		Surnames    string `json:"surnames"`
		CommonWords string `json:"common_words"`
	} `json:"dictionary"`
}

type Node struct {
	Op  string `json:"op"`
	ID  string `json:"id"`  // op == "detector"
	Min int    `json:"min"` // op == "or"
	Of  []Node `json:"of"`  // op == "or" | "and"
}

type Profile struct {
	ProfileID string `json:"profile_id"`
	Match     Node   `json:"match"`
}

type Rules struct {
	SchemaVersion string            `json:"schema_version"`
	Validators    map[string]string `json:"validators"`
	Detectors     []Detector        `json:"detectors"`
	Profiles      []Profile         `json:"profiles"`
}

func collectRefs(n Node, refs map[string]bool) {
	if n.Op == "detector" {
		refs[n.ID] = true
		return
	}
	for _, c := range n.Of {
		collectRefs(c, refs)
	}
}

func main() {
	path := "config/rules.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	var r Rules
	if err := json.Unmarshal(raw, &r); err != nil {
		fmt.Fprintln(os.Stderr, "JSON parse FAILED:", err)
		os.Exit(1)
	}

	fmt.Printf("schema: %s\n", r.SchemaVersion)
	fmt.Printf("detectors: %d   profiles: %d   validators declared: %d\n\n",
		len(r.Detectors), len(r.Profiles), len(r.Validators))

	defined := map[string]bool{}
	patternCount, failCount := 0, 0
	declaredValidators := map[string]bool{}
	for k := range r.Validators {
		declaredValidators[k] = true
	}

	fmt.Println("== Detector pattern compilation (RE2 / LOCAL_CAPABLE check) ==")
	for _, d := range r.Detectors {
		defined[d.ID] = true
		status := "OK"
		for i, p := range d.Patterns {
			patternCount++
			if _, err := regexp.Compile(p); err != nil {
				failCount++
				status = "FAIL"
				fmt.Printf("  [FAIL] %s pattern[%d]: %v\n", d.ID, i, err)
			}
		}
		// flag validators referenced but not declared
		for _, v := range d.Validators {
			if !declaredValidators[v] {
				fmt.Printf("  [WARN] %s references undeclared validator %q\n", d.ID, v)
			}
		}
		// dictionary detectors: check lexicon files exist and are non-empty
		if d.Kind == "dictionary" {
			if d.Dictionary == nil {
				failCount++
				status = "FAIL"
				fmt.Printf("  [FAIL] %s kind=dictionary but no dictionary config\n", d.ID)
			} else {
				for _, lex := range []string{d.Dictionary.GivenNames, d.Dictionary.Surnames, d.Dictionary.CommonWords} {
					if lex == "" {
						continue
					}
					if fi, err := os.Stat(lex); err != nil || fi.Size() == 0 {
						failCount++
						status = "FAIL"
						fmt.Printf("  [FAIL] %s lexicon missing/empty: %s\n", d.ID, lex)
					}
				}
			}
		}
		kind := d.Kind
		if kind == "" {
			kind = "regex"
		}
		fmt.Printf("  %-18s %-4s  kind=%-10s patterns=%d validators=%v\n", d.ID, status, kind, len(d.Patterns), d.Validators)
	}

	fmt.Println("\n== Profile reference resolution ==")
	refProblems := 0
	for _, p := range r.Profiles {
		refs := map[string]bool{}
		collectRefs(p.Match, refs)
		missing := []string{}
		for ref := range refs {
			if !defined[ref] {
				missing = append(missing, ref)
			}
		}
		if len(missing) > 0 {
			refProblems++
			fmt.Printf("  [FAIL] %-12s missing detectors: %v\n", p.ProfileID, missing)
		} else {
			fmt.Printf("  %-12s OK (%d detector refs)\n", p.ProfileID, len(refs))
		}
	}

	fmt.Printf("\nSUMMARY: %d patterns, %d compile failures, %d profile ref problems\n",
		patternCount, failCount, refProblems)
	if failCount > 0 || refProblems > 0 {
		os.Exit(1)
	}
	fmt.Println("ALL GOOD — every pattern is RE2-compatible and every profile resolves.")
}
