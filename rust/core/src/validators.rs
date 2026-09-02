//! Deterministic post-match validators that cut false positives (Luhn, IBAN mod-97, ABA
//! checksum, VIN, SSN range rules, EIN prefix, NPI, DEA, ...). Names match the `validators`
//! keys in `../../../config/rules.json`. Ported from `internal/validators/validators.go`.
//!
//! `luhn`/`luhn9`/`npi` share a `luhn_sum_from` helper (the Go original duplicates the loop
//! three times with a different length gate / starting parity each time) — this is a faithful
//! simplification, not a behaviour change.

/// Reports whether `s` passes the named validator. Unknown validator => false.
pub fn run(name: &str, s: &str) -> bool {
    match name {
        "luhn_check" => luhn(s),
        "iban_mod97" => iban_mod97(s),
        "aba_checksum" => aba(s),
        "vin_check" => vin(s),
        "ssn_check" => ssn(s),
        "ein_prefix" => ein_prefix(s),
        "npi_check" => npi(s),
        "dea_check" => dea(s),
        "itin_check" => itin(s),
        "sin_check" => luhn9(s),
        "nir_check" => nir_fr(s),
        "de_tax_check" => de_tax_id(s),
        "es_dni_check" => es_dni(s),
        "bsn_check" => nl_bsn(s),
        _ => false,
    }
}

fn digits(s: &str) -> Vec<u32> {
    s.chars().filter(|c| c.is_ascii_digit()).map(|c| c as u32 - '0' as u32).collect()
}

/// Luhn checksum, doubling every second digit from the right; `alt` is the starting parity
/// (false for a plain Luhn number, true for NPI's 80840-prefixed variant).
fn luhn_sum_from(d: &[u32], mut alt: bool) -> u32 {
    let mut sum = 0u32;
    for &x in d.iter().rev() {
        let mut x = x;
        if alt {
            x *= 2;
            if x > 9 {
                x -= 9;
            }
        }
        sum += x;
        alt = !alt;
    }
    sum
}

fn luhn(s: &str) -> bool {
    let d = digits(s);
    if d.len() < 12 {
        return false;
    }
    luhn_sum_from(&d, false).is_multiple_of(10)
}

/// Luhn over exactly 9 digits (Canada SIN / similar).
fn luhn9(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 9 {
        return false;
    }
    luhn_sum_from(&d, false).is_multiple_of(10)
}

fn iban_len(country: &str) -> Option<usize> {
    Some(match country {
        "GB" | "DE" | "IE" => 22,
        "FR" | "IT" => 27,
        "ES" | "SE" => 24,
        "NL" | "DK" | "FI" => 18,
        "BE" => 16,
        "CH" => 21,
        "PT" => 25,
        "AT" | "LU" => 20,
        "NO" => 15,
        "PL" => 28,
        _ => return None,
    })
}

fn iban_mod97(s: &str) -> bool {
    let s: String = s.chars().filter(|c| *c != ' ').collect::<String>().to_uppercase();
    if s.len() < 15 || s.len() > 34 {
        return false;
    }
    if let Some(want) = iban_len(&s[..2])
        && s.len() != want
    {
        return false;
    }
    let rearranged = format!("{}{}", &s[4..], &s[..4]);
    let mut rem: u64 = 0;
    for c in rearranged.chars() {
        if c.is_ascii_digit() {
            rem = (rem * 10 + (c as u64 - '0' as u64)) % 97;
        } else if c.is_ascii_uppercase() {
            let v = (c as u64 - 'A' as u64) + 10; // two-digit number
            rem = (rem * 100 + v) % 97;
        } else {
            return false;
        }
    }
    rem == 1
}

fn aba(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 9 {
        return false;
    }
    let sum = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8]);
    sum.is_multiple_of(10)
}

fn vin_translate(c: u8) -> Option<i32> {
    Some(match c {
        b'A' => 1,
        b'B' => 2,
        b'C' => 3,
        b'D' => 4,
        b'E' => 5,
        b'F' => 6,
        b'G' => 7,
        b'H' => 8,
        b'J' => 1,
        b'K' => 2,
        b'L' => 3,
        b'M' => 4,
        b'N' => 5,
        b'P' => 7,
        b'R' => 9,
        b'S' => 2,
        b'T' => 3,
        b'U' => 4,
        b'V' => 5,
        b'W' => 6,
        b'X' => 7,
        b'Y' => 8,
        b'Z' => 9,
        _ => return None,
    })
}

fn vin(s: &str) -> bool {
    let s = s.trim().to_uppercase();
    let bytes = s.as_bytes();
    if bytes.len() != 17 {
        return false;
    }
    const WEIGHTS: [i32; 17] = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];
    let mut sum: i32 = 0;
    for i in 0..17 {
        let c = bytes[i];
        let v = if c.is_ascii_digit() {
            (c - b'0') as i32
        } else {
            match vin_translate(c) {
                Some(t) => t,
                None => return false,
            }
        };
        sum += v * WEIGHTS[i];
    }
    let check = sum % 11;
    let cc = bytes[8];
    if check == 10 {
        cc == b'X'
    } else {
        cc.is_ascii_digit() && (cc - b'0') as i32 == check
    }
}

fn ssn(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 9 {
        return false;
    }
    let area = d[0] * 100 + d[1] * 10 + d[2];
    let group = d[3] * 10 + d[4];
    let serial = d[5] * 1000 + d[6] * 100 + d[7] * 10 + d[8];
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }
    group != 0 && serial != 0
}

/// IRS valid EIN campus prefixes (first two digits).
const EIN_OK: &[u32] = &[
    1, 2, 3, 4, 5, 6, 10, 11, 12, 13, 14, 15, 16, 20, 21, 22, 23, 24, 25, 26, 27, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
    50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 71, 72, 73, 74, 75, 76, 77, 80, 81, 82, 83, 84, 85, 86, 87, 88, 90, 91, 92, 93,
    94, 95, 98, 99,
];

fn ein_prefix(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 9 {
        return false;
    }
    EIN_OK.contains(&(d[0] * 10 + d[1]))
}

fn npi(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 10 {
        return false;
    }
    let mut all: Vec<u32> = vec![8, 0, 8, 4, 0]; // NPI namespace prefix 80840
    all.extend_from_slice(&d[..9]);
    let sum = luhn_sum_from(&all, true);
    (10 - (sum % 10)) % 10 == d[9]
}

/// US Individual Taxpayer ID — 9 digits, leads with 9, middle (group) digits in IRS ranges
/// 50-65, 70-88, 90-92, 94-99.
fn itin(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 9 || d[0] != 9 {
        return false;
    }
    let g = d[3] * 10 + d[4];
    matches!(g, 50..=65 | 70..=88 | 90..=92 | 94..=99)
}

/// France INSEE / social-security number (NIR). 15 digits; the last 2 are a key
/// = 97 - (first 13 digits mod 97).
fn nir_fr(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 15 {
        return false;
    }
    let mut n: i64 = 0;
    for &x in &d[..13] {
        n = n * 10 + x as i64;
    }
    let key = 97 - (n % 97);
    (d[13] * 10 + d[14]) as i64 == key
}

/// German tax identification number (IdNr), 11 digits, ISO 7064 MOD 11,10.
fn de_tax_id(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 11 {
        return false;
    }
    let mut product: i32 = 10;
    for &x in &d[..10] {
        let mut sum = (x as i32 + product) % 10;
        if sum == 0 {
            sum = 10;
        }
        product = (sum * 2) % 11;
    }
    let mut check = 11 - product;
    if check == 10 {
        check = 0;
    }
    check == d[10] as i32
}

/// Spanish DNI — 8 digits + a letter computed as `table[n mod 23]`.
fn es_dni(s: &str) -> bool {
    let s: String = s.trim().replace('-', "").to_uppercase();
    if s.len() != 9 {
        return false;
    }
    let bytes = s.as_bytes();
    if !bytes[..8].iter().all(u8::is_ascii_digit) {
        return false;
    }
    if !bytes[8].is_ascii_uppercase() {
        return false;
    }
    let n: u32 = match s[..8].parse() {
        Ok(v) => v,
        Err(_) => return false,
    };
    const TABLE: &[u8] = b"TRWAGMYFPDXBNJZSQVHLCKE";
    TABLE[(n % 23) as usize] == bytes[8]
}

/// Dutch BSN — 9 digits passing the weighted 11-test.
fn nl_bsn(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 9 {
        return false;
    }
    const W: [i32; 8] = [9, 8, 7, 6, 5, 4, 3, 2];
    let mut all_zero = true;
    let mut sum: i32 = 0;
    for i in 0..8 {
        sum += d[i] as i32 * W[i];
        all_zero &= d[i] == 0;
    }
    sum -= d[8] as i32;
    all_zero &= d[8] == 0;
    !all_zero && sum % 11 == 0
}

fn dea(s: &str) -> bool {
    let s = s.trim().to_uppercase();
    let bytes = s.as_bytes();
    if bytes.len() != 9 {
        return false;
    }
    if !bytes[0].is_ascii_uppercase() {
        return false;
    }
    if !(bytes[1].is_ascii_uppercase() || bytes[1] == b'9') {
        return false;
    }
    if !bytes[2..9].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let dg = |i: usize| -> i32 { (bytes[i] - b'0') as i32 };
    let sum = (dg(2) + dg(4) + dg(6)) + 2 * (dg(3) + dg(5) + dg(7));
    sum % 10 == dg(8)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported directly from internal/validators/validators_test.go.
    #[test]
    fn national_id_validators() {
        let cases = [
            ("sin_check", "046454286", "046454287"),
            ("es_dni_check", "12345678Z", "12345678A"),
            ("bsn_check", "111222333", "111222334"),
            ("de_tax_check", "86095742719", "86095742718"),
        ];
        for (name, good, bad) in cases {
            assert!(run(name, good), "{name}: {good:?} should be valid");
            assert!(!run(name, bad), "{name}: {bad:?} should be invalid");
        }
    }

    #[test]
    fn nir() {
        let base = "2550814168025"; // 13 digits
        let n: i64 = base.chars().fold(0, |acc, c| acc * 10 + (c as i64 - '0' as i64));
        let key = 97 - (n % 97);
        let good = format!("{base}{key:02}");
        assert!(run("nir_check", &good), "nir_check: {good:?} should be valid");
        let bad = format!("{base}{:02}", (key % 97) + 1);
        assert!(!run("nir_check", &bad), "nir_check: {bad:?} should be invalid");
    }

    // The Go test suite doesn't cover these — synthetic vectors below (no real identifiers).
    #[test]
    fn luhn_check() {
        // Well-known Visa test card number (not a real card); luhn_check requires >=12 digits,
        // so an 11-digit classic Luhn test string (e.g. "79927398713") is rejected at the gate.
        assert!(run("luhn_check", "4111111111111111"));
        assert!(!run("luhn_check", "4111111111111112"));
    }

    #[test]
    fn aba_checksum() {
        assert!(run("aba_checksum", "021000021"));
        assert!(!run("aba_checksum", "021000022"));
    }

    #[test]
    fn vin_check() {
        assert!(run("vin_check", "1M8GDM9AXKP042788"));
        assert!(!run("vin_check", "1M8GDM9A0KP042788"));
    }

    #[test]
    fn ssn_check() {
        assert!(run("ssn_check", "123456789"));
        assert!(!run("ssn_check", "666456789"));
    }

    #[test]
    fn ein_prefix() {
        assert!(run("ein_prefix", "101234567"));
        assert!(!run("ein_prefix", "091234567"));
    }

    #[test]
    fn npi_check() {
        assert!(run("npi_check", "1234567893"));
        assert!(!run("npi_check", "1234567890"));
    }

    #[test]
    fn itin_check() {
        assert!(run("itin_check", "900701234"));
        assert!(!run("itin_check", "900011234"));
    }

    #[test]
    fn dea_check() {
        assert!(run("dea_check", "AB1234563"));
        assert!(!run("dea_check", "AB1234564"));
    }

    #[test]
    fn iban_mod97() {
        assert!(run("iban_mod97", "GB82WEST12345698765432"));
        assert!(!run("iban_mod97", "GB82WEST12345698765431"));
    }

    #[test]
    fn unknown_validator() {
        assert!(!run("not_a_real_validator", "anything"));
    }
}
