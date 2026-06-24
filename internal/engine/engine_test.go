package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
func TestCorpus(t *testing.T) {
	db := loadDB(t)
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
