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

// TestCorpus runs every corpus file and checks verdict + expected profiles.
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
		Verdict  string   `json:"verdict"`
		Profiles []string `json:"profiles"`
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
			if v.Disposition != want.Verdict {
				t.Errorf("verdict = %s, want %s", v.Disposition, want.Verdict)
			}
			got := map[string]bool{}
			for _, p := range v.Profiles {
				got[p.ProfileID] = true
			}
			for _, wp := range want.Profiles {
				if !got[wp] {
					var have []string
					for _, p := range v.Profiles {
						have = append(have, p.ProfileID)
					}
					t.Errorf("missing profile %s (got %s)", wp, strings.Join(have, ","))
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
		file      string
		verdict   string
		profile   string // one required profile ("" = none)
		wantLabel bool   // expect >=1 sensitivity label
	}{
		{"hipaa.docx", Block, "PHI_HIPAA", false},
		{"clean.docx", Allow, "", false},
		{"pci.xlsx", Block, "PCI", false},
		{"financial.pptx", Block, "FINANCIAL", false},
		{"pii.pdf", Block, "US_PII", false},
		{"legacy.doc", Escalate, "", false},        // OLE: extraction fails -> escalate
		{"labeled.docx", Block, "", true},          // MSIP metadata label -> BLOCK
		{"footer_marked.docx", Escalate, "", true}, // body marking -> ESCALATE
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
			if v.Disposition != c.verdict {
				t.Errorf("%s: verdict = %s, want %s", c.file, v.Disposition, c.verdict)
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

// TestEarlyExit verifies the short-circuit: a PII-saturated buffer reaches BLOCK
// without scanning every detector, and the verdict is still correct.
func TestEarlyExit(t *testing.T) {
	db := loadDB(t)
	if !db.Conf.EarlyExit.Enabled {
		t.Skip("early-exit disabled in config")
	}
	text := makeLarge(200 * 1024) // dense PII in every block
	v := Inspect("dense", text, db)
	if v.Disposition != Block {
		t.Errorf("verdict = %s, want BLOCK", v.Disposition)
	}
	if !v.ShortCircuit {
		t.Errorf("expected short-circuit on a saturated buffer")
	}

	// With early-exit off, the same buffer must still BLOCK (and report more).
	db.Conf.EarlyExit.Enabled = false
	full := Inspect("dense", text, db)
	if full.Disposition != Block {
		t.Errorf("full-scan verdict = %s, want BLOCK", full.Disposition)
	}
	if len(full.Profiles) < len(v.Profiles) {
		t.Errorf("full scan should report >= profiles than short-circuit (%d vs %d)",
			len(full.Profiles), len(v.Profiles))
	}
}

// TestSizeGate verifies head/tail extraction + coverage-aware escalation:
// PII buried in the skipped middle yields ESCALATE; PII in the tail is caught.
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
	if !v.Partial {
		t.Errorf("mid.txt: expected partial coverage")
	}
	if v.Disposition != Escalate {
		t.Errorf("mid.txt: verdict = %s, want ESCALATE (middle PII not seen)", v.Disposition)
	}

	// PII in the tail window -> caught -> BLOCK.
	tailPII := write("tail.txt",
		filler+filler+" payment card 4111111111111111 on file.\n")
	v2, err := InspectFile(tailPII, db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !v2.Partial {
		t.Errorf("tail.txt: expected partial coverage")
	}
	if v2.Disposition != Block {
		t.Errorf("tail.txt: verdict = %s, want BLOCK (tail PII seen)", v2.Disposition)
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
