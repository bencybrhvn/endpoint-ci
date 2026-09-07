package validators

import (
	"fmt"
	"testing"
)

// known-valid values for the national-ID checksums + a tweaked invalid each.
func TestNationalIDValidators(t *testing.T) {
	cases := []struct {
		name, good, bad string
	}{
		{"sin_check", "046454286", "046454287"},    // Canada SIN (Luhn)
		{"es_dni_check", "12345678Z", "12345678A"}, // Spain DNI
		{"bsn_check", "111222333", "111222334"},    // Netherlands BSN
		{"de_tax_check", "86095742719", "86095742718"},
		{"bic_country_check", "DEUTDEFF", "DEUTXXFF"}, // well-known BIC; XX isn't a real country
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !Run(c.name, c.good) {
				t.Errorf("%s: %q should be valid", c.name, c.good)
			}
			if Run(c.name, c.bad) {
				t.Errorf("%s: %q should be invalid", c.name, c.bad)
			}
		})
	}
}

func TestBICCountry(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"DEUTDEFF", true},     // 8-char, real country code (DE)
		{"DEUTDEFF500", true},  // 11-char branch form
		{"deutdeff", true},     // lowercase input
		{"DEUTXXFF", false},    // XX isn't an ISO 3166-1 alpha-2 code
		{"EXTERIOR", false},    // real Nucleuz-corpus false positive: an 8-char capitalized
		{"APPLICATION", false}, // word, BIC-shaped by coincidence, country field isn't real
	}
	for _, c := range cases {
		if got := Run("bic_country_check", c.s); got != c.want {
			t.Errorf("bic_country_check(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

// France NIR: build a valid number from a 13-digit base, confirm the key check.
func TestNIR(t *testing.T) {
	base := "2550814168025" // 13 digits
	var n int64
	for _, r := range base {
		n = n*10 + int64(r-'0')
	}
	key := 97 - (n % 97)
	good := base + fmt.Sprintf("%02d", key)
	if !Run("nir_check", good) {
		t.Errorf("nir_check: %q should be valid", good)
	}
	bad := base + fmt.Sprintf("%02d", (key%97)+1)
	if Run("nir_check", bad) {
		t.Errorf("nir_check: %q should be invalid", bad)
	}
}
