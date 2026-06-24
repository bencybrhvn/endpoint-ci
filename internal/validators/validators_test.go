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
