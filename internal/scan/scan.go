// Package scan runs the leaf detectors over a text buffer and produces a
// per-detector result with a confidence score and a "fired" flag.
package scan

import (
	"runtime"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/cyberhaven/endpoint-ci/internal/rules"
	"github.com/cyberhaven/endpoint-ci/internal/validators"
)

type Result struct {
	ID             string
	Name           string
	RawCount       int
	ValidatedCount int
	KeywordFound   bool
	Confidence     int
	Fired          bool
	Samples        []string
}

// Ctx holds the once-per-buffer work (lowercasing + the single multi-pattern
// prefilter pass) so the engine can scan detector subsets without redoing it.
type Ctx struct {
	text, lower string
	litPresent  []bool
	hasDigit    bool
}

// NewCtx runs the one-pass prefilter (Aho-Corasick literals + digit presence).
func NewCtx(text string, db *rules.DB) *Ctx {
	c := &Ctx{text: text, lower: strings.ToLower(text)}
	if db.LitMatcher != nil {
		c.litPresent = db.LitMatcher.Present(text)
	}
	c.hasDigit = strings.ContainsAny(text, "0123456789")
	return c
}

// ScanDetectors scans the given detectors over the buffer, in parallel across
// cores (detectors are independent and read-only). Prefilter-skipped detectors
// are dropped cheaply. Matches may overlap across detectors, so each scans
// separately — a single combined alternation would let them steal each other's
// matches.
func (c *Ctx) ScanDetectors(db *rules.DB, dets []*rules.Detector) map[string]*Result {
	out := map[string]*Result{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.NumCPU())
	for _, d := range dets {
		if d.Kind != "dictionary" && skipByPrefilter(d, c.litPresent, c.hasDigit) {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(d *rules.Detector) {
			defer wg.Done()
			defer func() { <-sem }()
			var r *Result
			if d.Kind == "dictionary" {
				r = scanDictionary(c.text, d, db)
			} else {
				r = scanRegex(c.text, c.lower, d, db)
			}
			if r != nil {
				mu.Lock()
				out[d.ID] = r
				mu.Unlock()
			}
		}(d)
	}
	wg.Wait()
	return out
}

// Scan evaluates every detector (convenience: one batch, no early exit).
func Scan(text string, db *rules.DB) map[string]*Result {
	return NewCtx(text, db).ScanDetectors(db, db.Detectors)
}

// skipByPrefilter reports whether a detector can be skipped without running its
// regex: a literal-anchored detector with none of its literals present, or a
// needs-digit detector in a buffer with no digits.
func skipByPrefilter(d *rules.Detector, litPresent []bool, hasDigit bool) bool {
	pf := d.Prefilter
	if pf == nil {
		return false
	}
	if len(pf.LitIdx) > 0 {
		any := false
		for _, ix := range pf.LitIdx {
			if litPresent != nil && litPresent[ix] {
				any = true
				break
			}
		}
		if !any {
			return true
		}
	}
	if pf.NeedsDigit && !hasDigit {
		return true
	}
	return false
}

func scanRegex(text, lower string, d *rules.Detector, db *rules.DB) *Result {
	// Context-gated (best-effort) detectors can't fire without a keyword anywhere
	// in the file — skip the regex pass entirely if none is present.
	if d.BestEffort && !containsAnyKeyword(lower, d.Keywords) {
		return nil
	}
	var strs []string
	var positions []int
	for _, re := range d.Patterns {
		// Cap matches: we never need more than a handful to satisfy confidence
		// boosts and profile thresholds, and FindAllStringIndex stops scanning
		// once the cap is hit — bounding cost on match-dense files.
		for _, loc := range re.FindAllStringIndex(text, matchCap) {
			strs = append(strs, text[loc[0]:loc[1]])
			positions = append(positions, loc[0])
		}
	}
	return computeRegexResult(d, strs, positions, lower, db)
}

// matchCap bounds matches per detector. Far above any profile min_count or the
// instance-boost ceiling (3), so it never changes verdicts in practice.
const matchCap = 64

// computeRegexResult turns collected matches into a scored detector result.
func computeRegexResult(d *rules.Detector, strs []string, positions []int, lower string, db *rules.DB) *Result {
	// Context-gated (best-effort) detectors can't fire without a keyword anywhere.
	if d.BestEffort && !containsAnyKeyword(lower, d.Keywords) {
		return nil
	}
	if len(strs) == 0 {
		return nil
	}

	validated := 0
	hasValidators := len(d.Validators) > 0
	for _, s := range strs {
		if !hasValidators {
			continue
		}
		ok := true
		for _, v := range d.Validators {
			if !validators.Run(v, s) {
				ok = false
				break
			}
		}
		if ok {
			validated++
		}
	}

	kw := keywordNear(lower, positions, d.Keywords, db.Conf.KeywordWindow)

	conf := d.BaseConfidence
	if hasValidators && validated > 0 {
		conf += db.Conf.ValidatorBoost
	}
	if kw {
		conf += db.Conf.KeywordBoost
	}
	extra := len(strs) - 1
	if extra > db.Conf.MaxInstanceBoosts {
		extra = db.Conf.MaxInstanceBoosts
	}
	conf += extra * db.Conf.InstanceBoost
	if conf > 100 {
		conf = 100
	}

	fired := conf >= db.Conf.DefaultFireThreshold
	if hasValidators && validated == 0 { // validator exists but nothing validated => suppress
		fired = false
	}
	if d.BestEffort && !kw { // context-gated detectors need a nearby keyword
		fired = false
	}

	vc := validated
	if !hasValidators {
		vc = len(strs)
	}
	res := &Result{ID: d.ID, Name: d.Name, RawCount: len(strs), ValidatedCount: vc,
		KeywordFound: kw, Confidence: conf, Fired: fired}
	for i, s := range strs {
		if i >= 3 {
			break
		}
		res.Samples = append(res.Samples, s)
	}
	return res
}

func containsAnyKeyword(lower string, keywords []string) bool {
	for _, k := range keywords {
		if strings.Contains(lower, strings.ToLower(k)) {
			return true
		}
	}
	return false
}

func keywordNear(lower string, positions []int, keywords []string, window int) bool {
	if len(keywords) == 0 {
		return false
	}
	for _, p := range positions {
		lo, hi := p-window, p+window
		if lo < 0 {
			lo = 0
		}
		if hi > len(lower) {
			hi = len(lower)
		}
		seg := lower[lo:hi]
		for _, k := range keywords {
			if strings.Contains(seg, strings.ToLower(k)) {
				return true
			}
		}
	}
	return false
}

// --- dictionary (person name) detector ---

type tok struct {
	start, end int
	cap        bool
}

// scanDictionary runs the gazetteer person-name detector. It lowercases only
// capitalised tokens (the only candidates), keeping the hot path cheap.
func scanDictionary(text string, d *rules.Detector, db *rules.DB) *Result {
	dc := d.Dict
	if dc == nil {
		return nil
	}
	toks := tokenize(text)
	low := func(t tok) string { return strings.ToLower(text[t.start:t.end]) }
	nameEvidence := func(lw string) bool { return (dc.Given[lw] || dc.Surn[lw]) && !dc.HighFreq[lw] }
	ctxKeywords := d.Keywords
	lower := strings.ToLower(text)

	fired, best := 0, 0
	maxSpan := dc.MaxSpanTokens
	if maxSpan == 0 {
		maxSpan = 3
	}
	var samples []string
	for i := 0; i < len(toks); {
		if !toks[i].cap {
			i++
			continue
		}
		j := i + 1
		for j < len(toks) && toks[j].cap && spacesOnly(text, toks[j-1], toks[j]) {
			j++
		}
		run := toks[i:j]
		hasTitle := i > 0 && dc.TitleSet[low(toks[i-1])] && spacesOnly(text, toks[i-1], toks[i])
		start := 0
		if dc.TitleSet[low(run[0])] {
			hasTitle = true
			start = 1
		}
		span := run[start:]
		if len(span) > maxSpan {
			span = span[:maxSpan]
		}
		if len(span) >= 1 {
			score, nameToks := 0, 0
			for _, t := range span {
				if nameEvidence(low(t)) {
					score += dc.Scoring.NameEvidenceHit
					nameToks++
				}
			}
			if nameToks >= 2 {
				score += dc.Scoring.AdjacencyBonus
			}
			if hasTitle {
				score += dc.Scoring.TitleBonus
			}
			if keywordNear(lower, []int{span[0].start}, ctxKeywords, db.Conf.KeywordWindow) {
				score += dc.Scoring.KeywordBonus
			}
			conf := 40 + score*8
			if conf > 95 {
				conf = 95
			}
			if score >= dc.Scoring.FireThreshold {
				fired++
				if conf > best {
					best = conf
				}
				if len(samples) < 3 {
					parts := make([]string, len(span))
					for k, t := range span {
						parts[k] = text[t.start:t.end]
					}
					samples = append(samples, strings.Join(parts, " "))
				}
			}
		}
		i = j
	}
	if fired == 0 {
		return nil
	}
	return &Result{ID: d.ID, Name: d.Name, RawCount: fired, ValidatedCount: fired,
		KeywordFound: false, Confidence: best, Fired: true, Samples: samples}
}

// tokenize splits text into word tokens (single pass, no per-rune allocation).
func tokenize(text string) []tok {
	toks := make([]tok, 0, len(text)/6)
	i := 0
	for i < len(text) {
		r, sz := utf8.DecodeRuneInString(text[i:])
		if !unicode.IsLetter(r) {
			i += sz
			continue
		}
		start := i
		capit := unicode.IsUpper(r)
		i += sz
		for i < len(text) {
			rr, ss := utf8.DecodeRuneInString(text[i:])
			if unicode.IsLetter(rr) || rr == '\'' || rr == '-' {
				i += ss
			} else {
				break
			}
		}
		toks = append(toks, tok{start, i, capit})
	}
	return toks
}

func spacesOnly(text string, a, b tok) bool {
	if b.start < a.end {
		return false
	}
	for _, r := range text[a.end:b.start] {
		if r != ' ' && r != '\t' {
			return false
		}
	}
	return true
}
