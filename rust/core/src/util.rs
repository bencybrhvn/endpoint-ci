//! Small helpers shared across modules. Not part of the Go original — Go strings are arbitrary
//! bytes, so byte-offset slicing never panics there; Rust `str` must stay valid UTF-8, so every
//! module that ports Go's byte-offset slicing needs a boundary-safe cut. Factored out once
//! `extract.rs` and `scan.rs` both needed it, rather than duplicating it.

/// The largest index `<= idx` that lies on a UTF-8 character boundary of `s`.
pub(crate) fn floor_char_boundary(s: &str, idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    let mut idx = idx;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

/// The smallest index `>= idx` that lies on a UTF-8 character boundary of `s`.
pub(crate) fn ceil_char_boundary(s: &str, idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    let mut idx = idx;
    while idx < s.len() && !s.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries_on_ascii_are_identity() {
        assert_eq!(floor_char_boundary("hello", 3), 3);
        assert_eq!(ceil_char_boundary("hello", 3), 3);
    }

    #[test]
    fn boundaries_snap_around_multibyte_chars() {
        let s = "a€b"; // '€' is 3 bytes, at index 1..4
        assert_eq!(floor_char_boundary(s, 2), 1);
        assert_eq!(ceil_char_boundary(s, 2), 4);
    }

    #[test]
    fn out_of_range_clamps_to_len() {
        assert_eq!(floor_char_boundary("hi", 99), 2);
        assert_eq!(ceil_char_boundary("hi", 99), 2);
    }
}
