// Package engine orchestrates the inspection pipeline and builds a match report.
//
// This component INSPECTS and REPORTS only. It never decides an action
// (block/allow/quarantine): those are policy decisions made outside this
// component. The report says what was found — which profiles/data-types matched,
// how strongly, the contributing rules, sensitivity labels, and neutral facts
// about the scan (coverage, readability) — and a downstream policy engine
// decides what to do about it.
package engine

import (
	"os"
	"runtime"
	"sort"
	"time"

	"github.com/cyberhaven/endpoint-ci/internal/extract"
	"github.com/cyberhaven/endpoint-ci/internal/format"
	"github.com/cyberhaven/endpoint-ci/internal/label"
	"github.com/cyberhaven/endpoint-ci/internal/profile"
	"github.com/cyberhaven/endpoint-ci/internal/rules"
	"github.com/cyberhaven/endpoint-ci/internal/scan"
)

// Coverage describes how much of the content was inspected — a neutral fact for
// the policy layer, not an action.
const (
	CoverageFull      = "full"      // whole extracted body inspected
	CoveragePartial   = "partial"   // size gate: only head/tail windows inspected
	CoverageTruncated = "truncated" // extracted text hit the MaxBytes cap
)

// Report is the output of inspecting one file: the matches found and neutral
// facts about the scan. It carries no verdict/action.
type Report struct {
	File         string            `json:"file"`
	ScanPath     string            `json:"scan_path"` // always "local"
	FileType     string            `json:"file_type"`
	BytesSeen    int               `json:"bytes_seen"`
	Readable     bool              `json:"readable"` // false: encrypted/corrupt/binary — no body inspected
	Coverage     string            `json:"coverage"` // full | partial | truncated
	ShortCircuit bool              `json:"short_circuited,omitempty"`
	Note         string            `json:"note,omitempty"`
	ScanMicros   int64             `json:"scan_duration_us"`
	Profiles     []profile.Match   `json:"profiles"`
	Labels       []label.Match     `json:"labels,omitempty"`
	Detectors    []DetectorFinding `json:"detectors"`
}

// Matched reports whether any profile matched — a convenience for callers, not a
// policy signal.
func (r Report) Matched() bool { return len(r.Profiles) > 0 }

// HighConfidence reports whether any matched profile reached the given
// reporting-quality threshold. Used for summaries and early-exit; the policy
// engine may apply its own thresholds on top of the raw confidence scores.
func (r Report) HighConfidence(threshold int) bool {
	for _, m := range r.Profiles {
		if m.Confidence >= threshold {
			return true
		}
	}
	return false
}

type DetectorFinding struct {
	ID             string   `json:"id"` // rule_id (passes through unmodified)
	Name           string   `json:"name"`
	DataTypes      []string `json:"data_types"` // dataset_id(s) (pass through unmodified)
	RawCount       int      `json:"raw_count"`
	ValidatedCount int      `json:"validated_count"`
	Confidence     int      `json:"confidence"`
}

// orderByPriority sorts detectors so the strongest, most decisive ones run first
// (validator-backed and high base confidence), best-effort last. This makes the
// early-exit fire after the first batch on most match-dense files.
func orderByPriority(dets []*rules.Detector) []*rules.Detector {
	out := make([]*rules.Detector, len(dets))
	copy(out, dets)
	score := func(d *rules.Detector) int {
		s := d.BaseConfidence
		if len(d.Validators) > 0 {
			s += 20
		}
		if d.BestEffort {
			s -= 100
		}
		return s
	}
	sort.SliceStable(out, func(i, j int) bool { return score(out[i]) > score(out[j]) })
	return out
}

func hasHighConfidence(matches []profile.Match, threshold int) bool {
	for _, m := range matches {
		if m.Confidence >= threshold {
			return true
		}
	}
	return false
}

// InspectFile reads a file, detects its format, extracts text, then inspects.
func InspectFile(path string, db *rules.DB, cfg extract.Config) (Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Report{}, err
	}
	return InspectData(path, data, db, cfg), nil
}

// InspectData inspects an in-memory file: detect → extract → label → scan →
// report. No filesystem access, so it works in browser/WASM (where bytes come
// from JS) as well as on the endpoint.
func InspectData(name string, data []byte, db *rules.DB, cfg extract.Config) Report {
	res := extract.Extract(data, cfg)

	// Sensitivity-label fast-path (OOXML docProps / PDF XMP) runs on the raw bytes
	// regardless of text extraction — a labelled-but-unparseable doc must still be
	// reported. Metadata labels are machine-written, so they carry Source=metadata
	// for the policy layer to weigh.
	meta := label.Metadata(data, res.Type, db.LabelMarkers)

	// No body to scan: report readable=false plus whatever the metadata fast-path
	// found. Unsupported/binary vs encrypted/corrupt is distinguished only in the
	// note — both are simply "no body inspected" as far as the report is concerned.
	if res.Err != "" {
		r := Report{File: name, ScanPath: "local", FileType: res.Type.String(),
			BytesSeen: len(data), Readable: false, Coverage: CoverageFull, Labels: meta, Note: res.Err}
		if res.Type == format.Unsupported {
			r.Note = "unsupported/binary type — not content-inspected"
		}
		if len(meta) > 0 {
			r.Note = "sensitivity label present in metadata (body not extractable)"
		}
		return r
	}

	r := Inspect(name, res.Text, db)
	r.FileType = res.Type.String()
	switch {
	case res.Partial:
		r.Coverage = CoveragePartial
	case res.Truncated:
		r.Coverage = CoverageTruncated
	default:
		r.Coverage = CoverageFull
	}

	if len(meta) > 0 {
		r.Labels = append(meta, r.Labels...)
		if r.Note == "" {
			r.Note = "sensitivity label present in document metadata"
		}
	}
	return r
}

// Inspect runs detectors + profiles over text and builds a match report.
//
// Detectors are evaluated in priority-ordered batches (strong, validator-backed
// first). After each batch we re-evaluate profiles; once a high-confidence
// profile has matched (or matches saturate) we short-circuit — a hot-path cost
// optimisation. This can trim the reported profile set, so the flag is surfaced.
func Inspect(file, text string, db *rules.DB) Report {
	start := time.Now()

	ctx := scan.NewCtx(text, db)
	ordered := orderByPriority(db.Detectors)
	results := map[string]*scan.Result{}
	var matches []profile.Match
	totalMatches := 0
	shorted := false

	batch := runtime.NumCPU()
	if batch < 1 {
		batch = 1
	}
	ee := db.Conf.EarlyExit
	for i := 0; i < len(ordered); i += batch {
		end := i + batch
		if end > len(ordered) {
			end = len(ordered)
		}
		for id, rr := range ctx.ScanDetectors(db, ordered[i:end]) {
			results[id] = rr
			totalMatches += rr.RawCount
		}
		matches = profile.Evaluate(db, results)
		if ee.Enabled {
			if ee.StopOnHighConfidence && hasHighConfidence(matches, db.Conf.HighConfidenceThreshold) {
				shorted = true
				break
			}
			if ee.MaxTotalMatches > 0 && totalMatches >= ee.MaxTotalMatches {
				shorted = true
				break
			}
		}
	}
	elapsed := time.Since(start)

	r := Report{File: file, ScanPath: "local", BytesSeen: len(text), Readable: true,
		Coverage: CoverageFull, ScanMicros: elapsed.Microseconds(), Profiles: matches,
		ShortCircuit: shorted}
	if shorted {
		r.Note = "short-circuited: strong signal found, remaining detectors skipped"
	}

	// fired detectors, sorted by confidence desc for stable reporting
	var fired []*scan.Result
	for _, res := range results {
		if res.Fired {
			fired = append(fired, res)
		}
	}
	sort.Slice(fired, func(i, j int) bool {
		if fired[i].Confidence != fired[j].Confidence {
			return fired[i].Confidence > fired[j].Confidence
		}
		return fired[i].ID < fired[j].ID
	})
	for _, res := range fired {
		var dts []string
		if d, ok := db.Detector(res.ID); ok {
			dts = d.DataTypes
		}
		r.Detectors = append(r.Detectors, DetectorFinding{res.ID, res.Name, dts,
			res.RawCount, res.ValidatedCount, res.Confidence})
	}

	// Body-text sensitivity labels (distinctive markings) — reported, not actioned.
	if labels := label.Body(text, db.LabelMarkers); len(labels) > 0 {
		r.Labels = append(r.Labels, labels...)
	}
	return r
}
