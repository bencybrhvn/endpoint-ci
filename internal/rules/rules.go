// Package rules loads the local detection definition (config/rules.json):
// leaf detectors (regex or dictionary) and profile compositions. Compiling a
// pattern with Go's regexp IS the RE2 / LOCAL_CAPABLE compatibility check.
package rules

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/cyberhaven/endpoint-ci/internal/prefilter"
)

// Compatibility classes (spec §2.2).
const (
	LocalCapable = "LOCAL_CAPABLE"
	CloudOnly    = "CLOUD_ONLY"
)

type ConfidenceModel struct {
	ValidatorBoost       int       `json:"validator_boost"`
	KeywordBoost         int       `json:"keyword_boost"`
	InstanceBoost        int       `json:"instance_boost"`
	MaxInstanceBoosts    int       `json:"max_instance_boosts"`
	KeywordWindow        int       `json:"keyword_window"`
	DefaultFireThreshold int       `json:"default_fire_threshold"`
	BlockThreshold       int       `json:"block_threshold"`
	EarlyExit            EarlyExit `json:"early_exit"`
}

// EarlyExit short-circuits the engine once the verdict is already decided:
// stop scanning further detectors once a BLOCK-confidence profile has fired, or
// once total matches cross a saturation cap. The disposition can't change after
// BLOCK, so remaining work is pure cost.
type EarlyExit struct {
	Enabled         bool `json:"enabled"`
	StopOnBlock     bool `json:"stop_on_block"`
	MaxTotalMatches int  `json:"max_total_matches"`
}

type Scoring struct {
	NameEvidenceHit int `json:"name_evidence_hit"`
	AdjacencyBonus  int `json:"adjacency_bonus"`
	TitleBonus      int `json:"title_bonus"`
	KeywordBonus    int `json:"keyword_bonus"`
	FireThreshold   int `json:"fire_threshold"`
}

type Dictionary struct {
	GivenNames    string   `json:"given_names"`
	Surnames      string   `json:"surnames"`
	CommonWords   string   `json:"common_words"`
	Titles        []string `json:"titles"`
	MaxSpanTokens int      `json:"max_span_tokens"`
	KeywordWindow int      `json:"keyword_window"`
	Scoring       Scoring  `json:"scoring"`

	// loaded sets (not from JSON)
	Given    map[string]bool `json:"-"`
	Surn     map[string]bool `json:"-"`
	HighFreq map[string]bool `json:"-"`
	TitleSet map[string]bool `json:"-"`
}

// Prefilter is a cheap pre-check: skip this detector's regex unless one of its
// literals is present (Aho-Corasick) and/or the file contains a digit.
type Prefilter struct {
	Literals   []string `json:"literals"`
	NeedsDigit bool     `json:"needs_digit"`
	LitIdx     []int    `json:"-"` // indices into DB.LitMatcher
}

type Detector struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	Group          string      `json:"group"`
	Kind           string      `json:"kind"` // "" => regex, or "dictionary"
	DataTypes      []string    `json:"data_types"`
	PatternStrs    []string    `json:"patterns"`
	Validators     []string    `json:"validators"`
	Keywords       []string    `json:"keywords"`
	BaseConfidence int         `json:"base_confidence"`
	BestEffort     bool        `json:"best_effort"`
	Dict           *Dictionary `json:"dictionary"`
	Prefilter      *Prefilter  `json:"prefilter"`

	// compiled (not from JSON)
	Patterns []*regexp.Regexp `json:"-"`
	Combined string           `json:"-"` // valid patterns OR'd into one alternation
	Compat   string           `json:"-"`
}

type Node struct {
	Op           string `json:"op"`
	ID           string `json:"id"`
	Min          int    `json:"min"`
	MinCount     int    `json:"min_count"`
	MinValidated int    `json:"min_validated"`
	Of           []Node `json:"of"`
}

type Profile struct {
	ProfileID      string `json:"profile_id"`
	ProfileName    string `json:"profile_name"`
	DataType       string `json:"data_type"`
	VerdictOnMatch string `json:"verdict_on_match"`
	Match          Node   `json:"match"`
}

// LabelMarker matches sensitivity/classification labels (spec §4.5/§5):
// metadata property names and visible label strings.
type LabelMarker struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Strings            []string `json:"strings"`
	MetadataProperties []string `json:"metadata_properties"`
}

type DB struct {
	SchemaVersion string          `json:"schema_version"`
	Conf          ConfidenceModel `json:"confidence_model"`
	Detectors     []*Detector     `json:"detectors"`
	Profiles      []Profile       `json:"profiles"`
	LabelMarkers  []LabelMarker   `json:"label_markers"`

	// LitMatcher is the single Aho-Corasick automaton over every detector's
	// literal cues — one pass tells the scanner which detectors can match.
	LitMatcher *prefilter.Matcher `json:"-"`

	byID map[string]*Detector
}

func (db *DB) Detector(id string) (*Detector, bool) { d, ok := db.byID[id]; return d, ok }

// Load reads, parses, compiles patterns, and loads lexicons. Lexicon paths in
// the file are resolved relative to the current working directory.
func Load(path string) (*DB, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var db DB
	if err := json.Unmarshal(raw, &db); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	db.byID = map[string]*Detector{}
	for _, d := range db.Detectors {
		db.byID[d.ID] = d
		d.Compat = LocalCapable
		// Classify each pattern individually (the RE2/LOCAL_CAPABLE check),
		// then combine the valid ones into a single alternation so the scanner
		// makes one pass per detector instead of one pass per pattern.
		var valid []string
		for _, p := range d.PatternStrs {
			if _, err := regexp.Compile(p); err != nil {
				d.Compat = CloudOnly // RE2 rejected it (spec §2.2). Record, never crash.
				continue
			}
			valid = append(valid, p)
		}
		if len(valid) > 0 {
			d.Combined = "(?:" + strings.Join(valid, ")|(?:") + ")"
			if re, err := regexp.Compile(d.Combined); err == nil {
				d.Patterns = []*regexp.Regexp{re}
			} else {
				for _, p := range valid {
					if re, e := regexp.Compile(p); e == nil {
						d.Patterns = append(d.Patterns, re)
					}
				}
			}
		}
		if d.Kind == "dictionary" && d.Dict != nil {
			if err := loadDict(d.Dict); err != nil {
				return nil, fmt.Errorf("detector %s: %w", d.ID, err)
			}
		}
	}

	// Build one Aho-Corasick automaton across all detector literal cues.
	var lits []string
	for _, d := range db.Detectors {
		if d.Prefilter == nil {
			continue
		}
		for _, lit := range d.Prefilter.Literals {
			d.Prefilter.LitIdx = append(d.Prefilter.LitIdx, len(lits))
			lits = append(lits, lit)
		}
	}
	if len(lits) > 0 {
		db.LitMatcher = prefilter.New(lits)
	}
	return &db, nil
}

func loadDict(d *Dictionary) error {
	var err error
	if d.Given, err = loadSet(d.GivenNames); err != nil {
		return err
	}
	if d.Surn, err = loadSet(d.Surnames); err != nil {
		return err
	}
	if d.HighFreq, err = loadSet(d.CommonWords); err != nil {
		return err
	}
	d.TitleSet = map[string]bool{}
	for _, t := range d.Titles {
		d.TitleSet[strings.ToLower(t)] = true
	}
	return nil
}

func loadSet(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("lexicon %s: %w", path, err)
	}
	defer f.Close()
	s := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if w := strings.ToLower(strings.TrimSpace(sc.Text())); w != "" {
			s[w] = true
		}
	}
	return s, sc.Err()
}
