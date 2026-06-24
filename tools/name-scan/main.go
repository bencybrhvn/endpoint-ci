// Command name-scan is a reference implementation of the dictionary/gazetteer
// person-name detector described in docs/name-detection-design.md.
//
// Model: walk spans of capitalised tokens that are separated only by spaces
// (so sentence punctuation breaks a span). A token counts as name-evidence if
// it is in the given-name or surname list AND is NOT a top-frequency English
// word (high-frequency words like "Will"/"May"/"Contact" are excluded even when
// they appear in a name list — that is the precision lever). Score:
//
//	+nameHit       per name-evidence token
//	+adjacencyBonus if >=2 name-evidence tokens in the span
//	+titleBonus    if the span is preceded by / led by a title (Mr/Dr/...)
//	+keywordBonus  if a context keyword is within keywordWindow
//
// A span "fires" when score >= fireThreshold.
//
// Usage:
//
//	go run ./tools/name-scan path/to/file.txt
//	echo "Dr Jane Smith saw the patient" | go run ./tools/name-scan
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"unicode"
)

// tunables (mirror config/rules.json person_name.dictionary.scoring)
const (
	nameHit        = 2
	adjacencyBonus = 3
	titleBonus     = 3
	keywordBonus   = 1
	fireThreshold  = 5
	maxSpanTokens  = 3
	keywordWindow  = 200
	lexDir         = "config/lexicons"
)

var titles = map[string]bool{"mr": true, "mrs": true, "ms": true, "miss": true, "dr": true, "prof": true, "sir": true, "madam": true}
var ctxKeywords = []string{"name", "patient", "customer", "employee"}

func loadSet(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
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

type token struct {
	text       string
	lower      string
	start, end int // byte offsets
	cap        bool
}

func tokenize(text string) []token {
	var toks []token
	type rp struct {
		r   rune
		pos int
	}
	var rps []rp
	for p, r := range text {
		rps = append(rps, rp{r, p})
	}
	j := 0
	for j < len(rps) {
		if !unicode.IsLetter(rps[j].r) {
			j++
			continue
		}
		start := rps[j].pos
		var b strings.Builder
		end := start
		for j < len(rps) && (unicode.IsLetter(rps[j].r) || rps[j].r == '\'' || rps[j].r == '-') {
			b.WriteRune(rps[j].r)
			end = rps[j].pos + len(string(rps[j].r))
			j++
		}
		w := b.String()
		toks = append(toks, token{w, strings.ToLower(w), start, end, unicode.IsUpper([]rune(w)[0])})
	}
	return toks
}

// separatedBySpacesOnly reports whether the gap between two tokens contains only
// spaces/tabs (so "John Smith" stays one span but "Williams. Contact" splits).
func separatedBySpacesOnly(text string, a, b token) bool {
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

func keywordNear(text string, at int) bool {
	lo, hi := at-keywordWindow, at+keywordWindow
	if lo < 0 {
		lo = 0
	}
	if hi > len(text) {
		hi = len(text)
	}
	w := strings.ToLower(text[lo:hi])
	for _, k := range ctxKeywords {
		if strings.Contains(w, k) {
			return true
		}
	}
	return false
}

func main() {
	given, err := loadSet(lexDir + "/given_names.txt")
	if err != nil {
		fmt.Fprintln(os.Stderr, "load given:", err)
		os.Exit(1)
	}
	surn, err := loadSet(lexDir + "/surnames.txt")
	if err != nil {
		fmt.Fprintln(os.Stderr, "load surnames:", err)
		os.Exit(1)
	}
	highFreq, err := loadSet(lexDir + "/common_words.txt")
	if err != nil {
		fmt.Fprintln(os.Stderr, "load common:", err)
		os.Exit(1)
	}

	var text string
	if len(os.Args) > 1 {
		b, err := os.ReadFile(os.Args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "read:", err)
			os.Exit(1)
		}
		text = string(b)
	} else {
		b, _ := os.ReadFile("/dev/stdin")
		text = string(b)
	}

	// name-evidence: in a name list AND not a top-frequency word.
	nameEvidence := func(lw string) bool { return (given[lw] || surn[lw]) && !highFreq[lw] }

	toks := tokenize(text)
	fired := 0
	for i := 0; i < len(toks); {
		if !toks[i].cap {
			i++
			continue
		}
		// extend run across capitalised tokens separated only by spaces
		j := i + 1
		for j < len(toks) && toks[j].cap && separatedBySpacesOnly(text, toks[j-1], toks[j]) {
			j++
		}
		run := toks[i:j]

		hasTitle := i > 0 && titles[toks[i-1].lower] && separatedBySpacesOnly(text, toks[i-1], toks[i])
		startIdx := 0
		if titles[run[0].lower] {
			hasTitle = true
			startIdx = 1
		}
		span := run[startIdx:]
		if len(span) > maxSpanTokens {
			span = span[:maxSpanTokens]
		}

		if len(span) >= 1 {
			score, nameTokens := 0, 0
			for _, t := range span {
				if nameEvidence(t.lower) {
					score += nameHit
					nameTokens++
				}
			}
			if nameTokens >= 2 {
				score += adjacencyBonus
			}
			if hasTitle {
				score += titleBonus
			}
			if keywordNear(text, span[0].start) {
				score += keywordBonus
			}

			parts := make([]string, len(span))
			for k, t := range span {
				parts[k] = t.text
			}
			conf := 40 + score*8
			if conf > 95 {
				conf = 95
			}
			verdict := "—"
			if score >= fireThreshold {
				verdict, fired = "FIRE", fired+1
			}
			if nameTokens > 0 || hasTitle {
				fmt.Printf("  [%-4s] score=%-3d conf=%-3d  %q\n", verdict, score, conf, strings.Join(parts, " "))
			}
		}
		i = j
	}
	fmt.Printf("\n%d name span(s) fired (threshold=%d)\n", fired, fireThreshold)
}
