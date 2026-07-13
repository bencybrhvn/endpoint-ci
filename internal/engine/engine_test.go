package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyberhaven/endpoint-ci/internal/extract"
	"github.com/cyberhaven/endpoint-ci/internal/rules"
)

// chdir to repo root so config/ and testdata/ paths resolve.
func init() {
	dir, _ := os.Getwd()
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			os.Chdir(dir)
			return
		}
		dir = filepath.Dir(dir)
	}
}

func loadDB(t testing.TB) *rules.DB {
	t.Helper()
	db, err := rules.Load("config/rules.json")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return db
}

// TestCorpus runs every corpus file and checks the reported profiles (and,
// where specified, whether a match reached the high-confidence threshold).
// Early-exit is disabled here so the FULL profile set is reported (detection
// completeness); the short-circuit fast path is covered by TestEarlyExit.
func TestCorpus(t *testing.T) {
	db := loadDB(t)
	db.Conf.EarlyExit.Enabled = false
	raw, err := os.ReadFile("testdata/corpus/expectations.json")
	if err != nil {
		t.Fatal(err)
	}
	var exp map[string]struct {
		Profiles       []string `json:"profiles"`
		HighConfidence *bool    `json:"high_confidence"` // optional: assert only when present
	}
	if err := json.Unmarshal(raw, &exp); err != nil {
		t.Fatal(err)
	}

	for name, want := range exp {
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join("testdata/corpus", name))
			if err != nil {
				t.Fatal(err)
			}
			v := Inspect(name, string(b), db)
			got := map[string]bool{}
			var have []string
			for _, p := range v.Profiles {
				got[p.ProfileID] = true
				have = append(have, p.ProfileID)
			}
			// A file expected to be clean must report zero profile matches.
			if len(want.Profiles) == 0 && len(v.Profiles) != 0 {
				t.Errorf("expected no profiles, got %s", strings.Join(have, ","))
			}
			for _, wp := range want.Profiles {
				if !got[wp] {
					t.Errorf("missing profile %s (got %s)", wp, strings.Join(have, ","))
				}
			}
			if want.HighConfidence != nil {
				hc := v.HighConfidence(db.Conf.HighConfidenceThreshold)
				if hc != *want.HighConfidence {
					t.Errorf("high_confidence = %v, want %v (profiles %s)", hc, *want.HighConfidence,
						strings.Join(have, ","))
				}
			}
		})
	}
}

// TestDocuments exercises the extraction layer (OOXML, PDF, encrypted) end to end.
func TestDocuments(t *testing.T) {
	db := loadDB(t)
	db.Conf.EarlyExit.Enabled = false // verify full profile set
	cases := []struct {
		file         string
		profile      string // one required profile ("" = none)
		wantLabel    bool   // expect >=1 sensitivity label
		wantReadable bool   // body was content-inspected
	}{
		{"hipaa.docx", "PHI_HIPAA", false, true},
		{"clean.docx", "", false, true},
		{"pci.xlsx", "PCI", false, true},
		{"financial.pptx", "FINANCIAL", false, true},
		{"pii.pdf", "US_PII", false, true},
		{"legacy.doc", "", false, false},       // OLE: extraction fails -> not readable
		{"labeled.docx", "", true, true},       // MSIP metadata label reported
		{"footer_marked.docx", "", true, true}, // body marking reported
		{"labeled.pdf", "", true, false},       // PDF XMP MSIP label reported; no text layer
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			path := filepath.Join("testdata/docs", c.file)
			if _, err := os.Stat(path); err != nil {
				t.Skipf("missing fixture %s", path)
			}
			v, err := InspectFile(path, db, extract.Config{})
			if err != nil {
				t.Fatal(err)
			}
			if v.Readable != c.wantReadable {
				t.Errorf("%s: readable = %v, want %v", c.file, v.Readable, c.wantReadable)
			}
			if c.profile != "" {
				found := false
				for _, p := range v.Profiles {
					if p.ProfileID == c.profile {
						found = true
					}
				}
				if !found {
					t.Errorf("%s: missing profile %s", c.file, c.profile)
				}
			}
			if c.wantLabel && len(v.Labels) == 0 {
				t.Errorf("%s: expected a sensitivity label", c.file)
			}
		})
	}
}

// TestEarlyExit verifies the short-circuit: a PII-saturated buffer produces a
// high-confidence match without scanning every detector, and the report is still
// correct.
func TestEarlyExit(t *testing.T) {
	db := loadDB(t)
	if !db.Conf.EarlyExit.Enabled {
		t.Skip("early-exit disabled in config")
	}
	th := db.Conf.HighConfidenceThreshold
	text := makeLarge(200 * 1024) // dense PII in every block
	v := Inspect("dense", text, db)
	if !v.HighConfidence(th) {
		t.Errorf("expected a high-confidence match on a saturated buffer")
	}
	if !v.ShortCircuit {
		t.Errorf("expected short-circuit on a saturated buffer")
	}

	// With early-exit off, the same buffer must still match strongly (and report more).
	db.Conf.EarlyExit.Enabled = false
	full := Inspect("dense", text, db)
	if !full.HighConfidence(th) {
		t.Errorf("full-scan: expected a high-confidence match")
	}
	if len(full.Profiles) < len(v.Profiles) {
		t.Errorf("full scan should report >= profiles than short-circuit (%d vs %d)",
			len(full.Profiles), len(v.Profiles))
	}
}

// TestSizeGate verifies head/tail extraction + coverage reporting: PII buried in
// the skipped middle is not matched but coverage is reported "partial"; PII in
// the tail window is caught.
func TestSizeGate(t *testing.T) {
	db := loadDB(t)
	dir := t.TempDir()
	filler := strings.Repeat("Lorem ipsum dolor sit amet consectetur. ", 4000) // ~160 KB

	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfg := extract.Config{MaxFileBytes: 64 << 10, HeadTailWindow: 8 << 10} // 64KB gate, 8KB windows

	// PII only in the middle (skipped by head/tail) -> partial + escalate.
	midPII := write("mid.txt",
		filler+" Card 4111111111111111. SSN 123-45-6789. "+filler)
	v, err := InspectFile(midPII, db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if v.Coverage != CoveragePartial {
		t.Errorf("mid.txt: coverage = %s, want partial", v.Coverage)
	}
	if v.Matched() {
		t.Errorf("mid.txt: expected no matches (middle PII not seen), got %d profiles", len(v.Profiles))
	}

	// PII in the tail window -> caught -> BLOCK.
	tailPII := write("tail.txt",
		filler+filler+" payment card 4111111111111111 on file.\n")
	v2, err := InspectFile(tailPII, db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if v2.Coverage != CoveragePartial {
		t.Errorf("tail.txt: coverage = %s, want partial", v2.Coverage)
	}
	if !v2.Matched() {
		t.Errorf("tail.txt: expected a match (tail PII seen), got none")
	}
}

// TestSourceCode checks the source-code classifier fires on real code and stays
// silent on the confusables (config/markup/prose) that naive detectors trip on.
func TestSourceCode(t *testing.T) {
	db := loadDB(t)
	db.Conf.EarlyExit.Enabled = false
	fires := func(text string) bool {
		v := Inspect("x", text, db)
		for _, p := range v.Profiles {
			if p.ProfileID == "SOURCE_CODE" {
				return true
			}
		}
		return false
	}

	goSrc := "" +
		"package store\n\nimport (\n\t\"errors\"\n\t\"sync\"\n)\n\n" +
		"// Cache is a tiny concurrency-safe key/value store.\n" +
		"type Cache struct {\n\tmu sync.Mutex\n\tm  map[string]int\n}\n\n" +
		"func New() *Cache {\n\treturn &Cache{m: make(map[string]int)}\n}\n\n" +
		"func (c *Cache) Get(k string) (int, error) {\n\tc.mu.Lock()\n\tdefer c.mu.Unlock()\n" +
		"\tv, ok := c.m[k]\n\tif !ok {\n\t\treturn 0, errors.New(\"missing\")\n\t}\n\treturn v, nil\n}\n\n" +
		"func (c *Cache) Set(k string, v int) {\n\tc.mu.Lock()\n\tc.m[k] = v\n\tc.mu.Unlock()\n}\n"
	if !fires(goSrc) {
		t.Error("expected SOURCE_CODE to fire on a Go snippet")
	}

	jsonBlob := "{\n  \"name\": \"svc\",\n  \"port\": 8080,\n  \"tags\": [\"a\", \"b\"],\n  \"nested\": {\"on\": true}\n}\n"
	if fires(jsonBlob) {
		t.Error("SOURCE_CODE should not fire on a JSON config blob")
	}

	prose := strings.Repeat("The quarterly report summarises our progress and outlines the plan. ", 12)
	if fires(prose) {
		t.Error("SOURCE_CODE should not fire on natural-language prose")
	}
}

func makeLarge(n int) string {
	block := "Lorem ipsum dolor sit amet. Contact john.doe@example.com or (415) 555-2671. " +
		"Card 4111111111111111. SSN 123-45-6789. NPI 1234567893. IBAN GB82WEST12345698765432.\n"
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(block)
	}
	return b.String()
}

func BenchmarkInspect500K(b *testing.B) {
	db := loadDB(b)
	text := makeLarge(500 * 1024)
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Inspect("large", text, db)
	}
}

func BenchmarkInspect8K(b *testing.B) {
	db := loadDB(b)
	text := makeLarge(8 * 1024)
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Inspect("typical", text, db)
	}
}

// BenchmarkInspectCode500K measures the cost of inspecting a large source-code
// buffer — the source-code classifier is on the hot path for every file.
func BenchmarkInspectCode500K(b *testing.B) {
	db := loadDB(b)
	block := "func handle(w http.ResponseWriter, r *http.Request) error {\n" +
		"\tid := r.URL.Query().Get(\"id\")\n\tif id == \"\" {\n\t\treturn errors.New(\"missing id\")\n\t}\n" +
		"\t// look up the record and return it\n\trec, err := store.Get(ctx, id)\n\tif err != nil {\n\t\treturn err\n\t}\n" +
		"\treturn json.NewEncoder(w).Encode(rec)\n}\n\n"
	var sb strings.Builder
	for sb.Len() < 500*1024 {
		sb.WriteString(block)
	}
	text := sb.String()
	b.SetBytes(int64(len(text)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Inspect("big.go", text, db)
	}
}
