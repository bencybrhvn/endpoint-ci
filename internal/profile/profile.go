// Package profile evaluates profile composition trees (and/or/detector with
// min/min_count/min_validated) over the leaf detector results.
package profile

import (
	"github.com/cyberhaven/endpoint-ci/internal/rules"
	"github.com/cyberhaven/endpoint-ci/internal/scan"
)

type Match struct {
	ProfileID   string `json:"profile_id"`
	ProfileName string `json:"profile_name"`
	DataType    string `json:"data_type"`
	Verdict     string `json:"verdict_on_match"` // configured verdict (e.g. BLOCK)
	Confidence  int    `json:"confidence"`       // representative confidence
}

// Evaluate returns the profiles that match the given detector results.
func Evaluate(db *rules.DB, results map[string]*scan.Result) []Match {
	var out []Match
	for _, p := range db.Profiles {
		if eval(p.Match, results) {
			out = append(out, Match{
				ProfileID:   p.ProfileID,
				ProfileName: p.ProfileName,
				DataType:    p.DataType,
				Verdict:     p.VerdictOnMatch,
				Confidence:  confidence(p.Match, results),
			})
		}
	}
	return out
}

func eval(n rules.Node, res map[string]*scan.Result) bool {
	switch n.Op {
	case "detector":
		r, ok := res[n.ID]
		if !ok || !r.Fired {
			return false
		}
		if n.MinValidated > 0 && r.ValidatedCount < n.MinValidated {
			return false
		}
		if n.MinCount > 0 && r.RawCount < n.MinCount {
			return false
		}
		return true
	case "or":
		min := n.Min
		if min == 0 {
			min = 1
		}
		c := 0
		for _, ch := range n.Of {
			if eval(ch, res) {
				c++
			}
		}
		return c >= min
	case "and":
		for _, ch := range n.Of {
			if !eval(ch, res) {
				return false
			}
		}
		return true
	}
	return false
}

// confidence: representative score of a matched profile = the max confidence
// among contributing (satisfied) detectors. Used to choose BLOCK vs ESCALATE.
func confidence(n rules.Node, res map[string]*scan.Result) int {
	switch n.Op {
	case "detector":
		if r, ok := res[n.ID]; ok && r.Fired {
			return r.Confidence
		}
		return 0
	case "or", "and":
		best := 0
		for _, ch := range n.Of {
			if eval(ch, res) {
				if c := confidence(ch, res); c > best {
					best = c
				}
			}
		}
		return best
	}
	return 0
}
