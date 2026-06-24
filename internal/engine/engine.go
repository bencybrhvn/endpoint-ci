// Package engine orchestrates the inspection pipeline and builds a verdict.
package engine

import (
	"sort"
	"time"

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
	File        string            `json:"file"`
	Disposition string            `json:"verdict"`
	ScanPath    string            `json:"scan_path"`
	BytesSeen   int               `json:"bytes_seen"`
	ScanMicros  int64             `json:"scan_duration_us"`
	Profiles    []profile.Match   `json:"profiles"`
	Detectors   []DetectorFinding `json:"detectors"`
}

type DetectorFinding struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	RawCount       int    `json:"raw_count"`
	ValidatedCount int    `json:"validated_count"`
	Confidence     int    `json:"confidence"`
}

// Inspect runs detectors + profiles over text and builds a verdict.
func Inspect(file, text string, db *rules.DB) Verdict {
	start := time.Now()
	results := scan.Scan(text, db)
	matches := profile.Evaluate(db, results)
	elapsed := time.Since(start)

	v := Verdict{File: file, ScanPath: "local", BytesSeen: len(text),
		ScanMicros: elapsed.Microseconds(), Profiles: matches}

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
