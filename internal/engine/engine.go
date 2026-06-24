// Package engine orchestrates the inspection pipeline and builds a verdict.
package engine

import (
	"os"
	"runtime"
	"sort"
	"time"

	"github.com/cyberhaven/endpoint-ci/internal/extract"
	"github.com/cyberhaven/endpoint-ci/internal/profile"
	"github.com/cyberhaven/endpoint-ci/internal/rules"
	"github.com/cyberhaven/endpoint-ci/internal/scan"
)

// Dispositions (spec §4.6). PoC reports — never enacts.
const (
	Allow    = "ALLOW"
	Block    = "BLOCK"
	Escalate = "ESCALATE"
)

type Verdict struct {
	File         string            `json:"file"`
	Disposition  string            `json:"verdict"`
	ScanPath     string            `json:"scan_path"`
	FileType     string            `json:"file_type"`
	BytesSeen    int               `json:"bytes_seen"`
	Truncated    bool              `json:"truncated,omitempty"`
	ShortCircuit bool              `json:"short_circuited,omitempty"`
	Note         string            `json:"note,omitempty"`
	ScanMicros   int64             `json:"scan_duration_us"`
	Profiles     []profile.Match   `json:"profiles"`
	Detectors    []DetectorFinding `json:"detectors"`
}

type DetectorFinding struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	RawCount       int    `json:"raw_count"`
	ValidatedCount int    `json:"validated_count"`
	Confidence     int    `json:"confidence"`
}

// orderByPriority sorts detectors so the strongest, most decisive ones run first
// (validator-backed and high base confidence), best-effort last. This makes the
// early-exit fire after the first batch on most BLOCK files.
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

func hasBlock(matches []profile.Match, threshold int) bool {
	for _, m := range matches {
		if m.Confidence >= threshold {
			return true
		}
	}
	return false
}

// InspectFile reads a file, detects its format, extracts text, then inspects.
// Extraction failure (encrypted/unsupported/corrupt) degrades to ESCALATE.
func InspectFile(path string, db *rules.DB, cfg extract.Config) (Verdict, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Verdict{}, err
	}
	res := extract.Extract(data, cfg)
	if res.Err != "" {
		return Verdict{File: path, ScanPath: "local", FileType: res.Type.String(),
			BytesSeen: len(data), Disposition: Escalate,
			Note: "extraction failed, escalate: " + res.Err}, nil
	}
	v := Inspect(path, res.Text, db)
	v.FileType = res.Type.String()
	v.Truncated = res.Truncated
	return v, nil
}

// Inspect runs detectors + profiles over text and builds a verdict.
//
// Detectors are evaluated in priority-ordered batches (strong, validator-backed
// first). After each batch we re-evaluate profiles; if a BLOCK-confidence verdict
// is already decided (or matches saturate), we short-circuit — the disposition
// can't change, so the remaining detectors are pure cost.
func Inspect(file, text string, db *rules.DB) Verdict {
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
		for id, r := range ctx.ScanDetectors(db, ordered[i:end]) {
			results[id] = r
			totalMatches += r.RawCount
		}
		matches = profile.Evaluate(db, results)
		if ee.Enabled {
			if ee.StopOnBlock && hasBlock(matches, db.Conf.BlockThreshold) {
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

	v := Verdict{File: file, ScanPath: "local", BytesSeen: len(text),
		ScanMicros: elapsed.Microseconds(), Profiles: matches, ShortCircuit: shorted}
	if shorted {
		v.Note = "short-circuited: verdict already decided, remaining detectors skipped"
	}

	// fired detectors, sorted by confidence desc for stable reporting
	var fired []*scan.Result
	for _, r := range results {
		if r.Fired {
			fired = append(fired, r)
		}
	}
	sort.Slice(fired, func(i, j int) bool {
		if fired[i].Confidence != fired[j].Confidence {
			return fired[i].Confidence > fired[j].Confidence
		}
		return fired[i].ID < fired[j].ID
	})
	for _, r := range fired {
		v.Detectors = append(v.Detectors, DetectorFinding{r.ID, r.Name, r.RawCount, r.ValidatedCount, r.Confidence})
	}

	// Disposition:
	//   BLOCK    if any profile matched with confidence >= block_threshold
	//   ESCALATE if a profile matched but only below block_threshold (uncertain)
	//   ALLOW    otherwise (incl. detector findings that form no profile)
	v.Disposition = Allow
	if len(matches) > 0 {
		v.Disposition = Escalate
		for _, m := range matches {
			if m.Confidence >= db.Conf.BlockThreshold {
				v.Disposition = Block
				break
			}
		}
	}
	return v
}
