// Package validators holds deterministic post-match validators that cut false
// positives (Luhn, IBAN mod-97, ABA checksum, VIN, SSN range rules, EIN prefix,
// NPI, DEA). Names match the "validators" keys in config/rules.json.
package validators

import "strings"

// Run reports whether s passes the named validator. Unknown validator => false.
func Run(name, s string) bool {
	if f, ok := registry[name]; ok {
		return f(s)
	}
	return false
}

var registry = map[string]func(string) bool{
	"luhn_check":   luhn,
	"iban_mod97":   ibanMod97,
	"aba_checksum": aba,
	"vin_check":    vin,
	"ssn_check":    ssn,
	"ein_prefix":   einPrefix,
	"npi_check":    npi,
	"dea_check":    dea,
	"itin_check":   itin,
	"sin_check":    luhn9,
}

func digits(s string) []int {
	var d []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			d = append(d, int(r-'0'))
		}
	}
	return d
}

func luhn(s string) bool {
	d := digits(s)
	if len(d) < 12 {
		return false
	}
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		x := d[i]
		if alt {
			if x *= 2; x > 9 {
				x -= 9
			}
		}
		sum += x
		alt = !alt
	}
	return sum%10 == 0
}

var ibanLen = map[string]int{
	"GB": 22, "DE": 22, "FR": 27, "ES": 24, "IT": 27, "NL": 18, "BE": 16,
	"CH": 21, "IE": 22, "PT": 25, "AT": 20, "SE": 24, "NO": 15, "DK": 18,
	"FI": 18, "PL": 28, "LU": 20,
}

func ibanMod97(s string) bool {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	if want, ok := ibanLen[s[:2]]; ok && len(s) != want {
		return false
	}
	rearr := s[4:] + s[:4]
	rem := 0
	for _, r := range rearr {
		switch {
		case r >= '0' && r <= '9':
			rem = (rem*10 + int(r-'0')) % 97
		case r >= 'A' && r <= 'Z':
			v := int(r - 'A' + 10) // two-digit number
			rem = (rem*100 + v) % 97
		default:
			return false
		}
	}
	return rem == 1
}

func aba(s string) bool {
	d := digits(s)
	if len(d) != 9 {
		return false
	}
	sum := 3*(d[0]+d[3]+d[6]) + 7*(d[1]+d[4]+d[7]) + (d[2] + d[5] + d[8])
	return sum%10 == 0
}

func vin(s string) bool {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) != 17 {
		return false
	}
	trans := map[byte]int{'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6, 'G': 7, 'H': 8,
		'J': 1, 'K': 2, 'L': 3, 'M': 4, 'N': 5, 'P': 7, 'R': 9,
		'S': 2, 'T': 3, 'U': 4, 'V': 5, 'W': 6, 'X': 7, 'Y': 8, 'Z': 9}
	weights := []int{8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2}
	sum := 0
	for i := 0; i < 17; i++ {
		c := s[i]
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
		default:
			t, ok := trans[c]
			if !ok {
				return false
			}
			v = t
		}
		sum += v * weights[i]
	}
	check := sum % 11
	cc := s[8]
	if check == 10 {
		return cc == 'X'
	}
	return cc >= '0' && cc <= '9' && int(cc-'0') == check
}

func ssn(s string) bool {
	d := digits(s)
	if len(d) != 9 {
		return false
	}
	area := d[0]*100 + d[1]*10 + d[2]
	group := d[3]*10 + d[4]
	serial := d[5]*1000 + d[6]*100 + d[7]*10 + d[8]
	if area == 0 || area == 666 || area >= 900 {
		return false
	}
	return group != 0 && serial != 0
}

// IRS valid EIN campus prefixes (first two digits).
var einOK = func() map[int]bool {
	m := map[int]bool{}
	for _, p := range []int{1, 2, 3, 4, 5, 6, 10, 11, 12, 13, 14, 15, 16, 20, 21, 22, 23, 24,
		25, 26, 27, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
		50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 71, 72, 73,
		74, 75, 76, 77, 80, 81, 82, 83, 84, 85, 86, 87, 88, 90, 91, 92, 93, 94, 95, 98, 99} {
		m[p] = true
	}
	return m
}()

func einPrefix(s string) bool {
	d := digits(s)
	if len(d) != 9 {
		return false
	}
	return einOK[d[0]*10+d[1]]
}

func npi(s string) bool {
	d := digits(s)
	if len(d) != 10 {
		return false
	}
	all := []int{8, 0, 8, 4, 0} // NPI namespace prefix 80840
	all = append(all, d[:9]...)
	sum, alt := 0, true
	for i := len(all) - 1; i >= 0; i-- {
		x := all[i]
		if alt {
			if x *= 2; x > 9 {
				x -= 9
			}
		}
		sum += x
		alt = !alt
	}
	return (10-(sum%10))%10 == d[9]
}

// itin: US Individual Taxpayer ID — 9 digits, leads with 9, middle (group)
// digits in IRS ranges 50-65, 70-88, 90-92, 94-99.
func itin(s string) bool {
	d := digits(s)
	if len(d) != 9 || d[0] != 9 {
		return false
	}
	g := d[3]*10 + d[4]
	switch {
	case g >= 50 && g <= 65, g >= 70 && g <= 88, g >= 90 && g <= 92, g >= 94 && g <= 99:
		return true
	}
	return false
}

// luhn9: Luhn over exactly 9 digits (Canada SIN / similar).
func luhn9(s string) bool {
	if len(digits(s)) != 9 {
		return false
	}
	d := digits(s)
	sum, alt := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		x := d[i]
		if alt {
			if x *= 2; x > 9 {
				x -= 9
			}
		}
		sum += x
		alt = !alt
	}
	return sum%10 == 0
}

func dea(s string) bool {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) != 9 {
		return false
	}
	if s[0] < 'A' || s[0] > 'Z' {
		return false
	}
	if !((s[1] >= 'A' && s[1] <= 'Z') || s[1] == '9') {
		return false
	}
	for i := 2; i < 9; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	dg := func(i int) int { return int(s[i] - '0') }
	sum := (dg(2) + dg(4) + dg(6)) + 2*(dg(3)+dg(5)+dg(7))
	return sum%10 == dg(8)
}
