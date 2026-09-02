//! Turns a file's bytes into inspectable plain text per format: plaintext direct, OOXML via
//! the `zip` crate + tag stripping, PDF text layer via the `pdf-extract` crate. Extraction
//! failures degrade gracefully (`err` set, never panic the caller). Ported from
//! `internal/extract/extract.go`.
//!
//! Adaptations forced by Rust's UTF-8 invariant (Go strings are arbitrary bytes; Rust `String`
//! must be valid UTF-8): raw-byte head/tail windows go through `String::from_utf8_lossy`
//! (replacing any split multi-byte sequence at the cut with U+FFFD) rather than a raw byte cast,
//! and every truncation snaps to the nearest UTF-8 char boundary (see `floor_char_boundary`/
//! `ceil_char_boundary`) instead of an arbitrary byte offset, which would otherwise panic.

use std::io::{Cursor, Read};
use std::panic::AssertUnwindSafe;

use crate::format::{self, Type};
use crate::util::{ceil_char_boundary, floor_char_boundary};

/// `None` means "use the default" for that field — mirrors the Go `Config`'s zero-value
/// behaviour (a zero field there is likewise indistinguishable from "not set").
#[derive(Debug, Clone, Copy, Default)]
pub struct Config {
    /// Cap on extracted text.
    pub max_bytes: Option<usize>,
    /// Size gate: above this, only head+tail are inspected.
    pub max_file_bytes: Option<usize>,
    /// Bytes per head/tail window when the gate trips.
    pub head_tail_window: Option<usize>,
}

pub const DEFAULT_MAX_BYTES: usize = 5 << 20;
pub const DEFAULT_MAX_FILE_BYTES: usize = 16 << 20;
pub const DEFAULT_HEAD_TAIL_WINDOW: usize = 64 << 10;

/// Bounds PDF text-layer output (defends against bomb PDFs).
const PDF_TEXT_CAP: usize = 32 << 20;

/// Separates the head and tail windows. Deliberately keyword-free so it can't create a false
/// match.
const GAP_MARKER: &str = "\n\n[--- size gate: middle of file not inspected ---]\n\n";

#[derive(Debug, Clone, Default)]
pub struct Extracted {
    pub format_type: Type,
    pub text: String,
    /// Hit `max_bytes`.
    pub truncated: bool,
    /// Size gate: only head+tail inspected, middle skipped.
    pub partial: bool,
    /// Set on extraction failure.
    pub err: Option<String>,
}

/// Detects the format of `data` and returns its inspectable text. Files larger than the size
/// gate are reduced to their head + tail windows (`partial`), so cost is bounded regardless of
/// file size; the caller treats partial coverage as inconclusive (escalate if otherwise clean).
pub fn extract(data: &[u8], cfg: Config) -> Extracted {
    let max = cfg.max_bytes.unwrap_or(DEFAULT_MAX_BYTES);
    let gate = cfg.max_file_bytes.unwrap_or(DEFAULT_MAX_FILE_BYTES);
    let win = cfg.head_tail_window.unwrap_or(DEFAULT_HEAD_TAIL_WINDOW);

    let t = format::detect(data);
    let mut r = Extracted {
        format_type: t,
        ..Default::default()
    };

    match t {
        Type::Plaintext => {
            // Apply the gate on the raw bytes so we never build a huge string.
            if gate > 0 && data.len() > gate {
                let head = String::from_utf8_lossy(&data[..win]).into_owned();
                let tail = String::from_utf8_lossy(&data[data.len() - win..]).into_owned();
                r.text = head_tail(&head, &tail);
                r.partial = true;
            } else {
                r.text = String::from_utf8_lossy(data).into_owned();
            }
        }
        Type::Docx | Type::Xlsx | Type::Pptx => match extract_ooxml(data, t) {
            Ok(txt) => r.text = txt,
            Err(e) => {
                r.err = Some(e);
                return r;
            }
        },
        Type::Pdf => match extract_pdf(data) {
            Ok(txt) => r.text = txt,
            Err(e) => {
                r.err = Some(e);
                return r;
            }
        },
        Type::Encrypted => {
            r.err = Some("encrypted or legacy office format (cannot read locally)".to_string());
            return r;
        }
        Type::Unknown | Type::Unsupported => {
            r.err = Some("unsupported file format".to_string());
            return r;
        }
    }

    // Size gate on extracted text (OOXML/PDF) once it's built.
    if !r.partial && gate > 0 && r.text.len() > gate {
        let head_end = floor_char_boundary(&r.text, win);
        let tail_start = ceil_char_boundary(&r.text, r.text.len() - win);
        let head = r.text[..head_end].to_string();
        let tail = r.text[tail_start..].to_string();
        r.text = head_tail(&head, &tail);
        r.partial = true;
    }
    if r.text.len() > max {
        let cut = floor_char_boundary(&r.text, max);
        r.text.truncate(cut);
        r.truncated = true;
    }
    r
}

fn head_tail(head: &str, tail: &str) -> String {
    format!("{head}{GAP_MARKER}{tail}")
}

// --- OOXML ---

/// Lists the zip entries that carry user text per OOXML type. Glob is a simple prefix/suffix
/// match (`prefix*` or exact).
fn ooxml_parts(t: Type) -> &'static [&'static str] {
    match t {
        Type::Docx => &["word/document.xml", "word/header*", "word/footer*", "docProps/core.xml", "docProps/custom.xml"],
        Type::Xlsx => &["xl/sharedStrings.xml", "docProps/core.xml", "docProps/custom.xml"],
        Type::Pptx => &["ppt/slides/slide*", "docProps/core.xml", "docProps/custom.xml"],
        _ => &[],
    }
}

fn extract_ooxml(data: &[u8], t: Type) -> Result<String, String> {
    let mut zr = zip::ZipArchive::new(Cursor::new(data)).map_err(|e| format!("open ooxml: {e}"))?;
    let patterns = ooxml_parts(t);

    // Stable order for deterministic output.
    let mut names: Vec<String> = zr.file_names().map(str::to_string).collect();
    names.sort();

    let mut out = String::new();
    for name in names {
        if !match_any(&name, patterns) {
            continue;
        }
        let Ok(file) = zr.by_name(&name) else { continue }; // skip unreadable part, don't fail whole file
        let mut raw = Vec::new();
        if file.take(DEFAULT_MAX_BYTES as u64).read_to_end(&mut raw).is_err() {
            continue;
        }
        out.push_str(&strip_xml(&raw));
        out.push('\n');
    }
    Ok(out)
}

fn match_any(name: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| match p.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == *p,
    })
}

/// Drops tags and returns text, inserting a space at each tag boundary so adjacent runs don't
/// fuse. Decodes the common XML entities.
fn strip_xml(raw: &[u8]) -> String {
    let mut out = Vec::with_capacity(raw.len());
    let mut in_tag = false;
    for &c in raw {
        match c {
            b'<' => {
                in_tag = true;
                out.push(b' ');
            }
            b'>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    decode_xml_entities(&String::from_utf8_lossy(&out))
}

/// A single left-to-right, non-overlapping pass (like Go's `strings.NewReplacer`): once an
/// entity is matched and replaced, scanning resumes after the *original* matched text — the
/// replacement itself is never rescanned. A naive chain of `.replace()` calls would rescan (e.g.
/// decoding `&amp;lt;` all the way to `<` instead of stopping at `&lt;`), which is wrong.
fn decode_xml_entities(s: &str) -> String {
    const ENTITIES: &[(&str, &str)] = &[("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", "\""), ("&apos;", "'")];
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    'outer: while i < s.len() {
        for (pat, repl) in ENTITIES {
            if s[i..].starts_with(pat) {
                out.push_str(repl);
                i += pat.len();
                continue 'outer;
            }
        }
        let ch = s[i..].chars().next().expect("i < s.len() implies a next char");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

// --- PDF (text layer) ---

fn extract_pdf(data: &[u8]) -> Result<String, String> {
    // pdf-extract (like ledongthuc/pdf) can panic on malformed PDFs; catch_unwind is our
    // recover().
    match std::panic::catch_unwind(AssertUnwindSafe(|| pdf_extract::extract_text_from_mem(data))) {
        Ok(Ok(mut text)) => {
            // Unlike Go's io.LimitReader over a streaming reader, pdf-extract materialises the
            // full string before we can cap it — this bounds the *reported* text, not the
            // allocation. The real DoS defence is process isolation at the CLI layer (see
            // ../../DECISIONS.md, "Real-world profiler + PDF DoS isolation").
            let cut = floor_char_boundary(&text, PDF_TEXT_CAP);
            text.truncate(cut);
            Ok(text)
        }
        Ok(Err(e)) => Err(format!("pdf text: {e}")),
        Err(panic) => Err(format!("pdf parse panic: {}", panic_message(&panic))),
    }
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture(name: &str) -> Vec<u8> {
        let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/docs")).join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {path:?}: {e}"))
    }

    #[test]
    fn plaintext_passes_through() {
        let r = extract(b"hello world, this is plain text", Config::default());
        assert_eq!(r.format_type, Type::Plaintext);
        assert_eq!(r.text, "hello world, this is plain text");
        assert!(!r.partial && !r.truncated && r.err.is_none());
    }

    #[test]
    fn unsupported_binary_reports_err() {
        let r = extract(&[0x01, 0x02, 0x00, 0xFF], Config::default());
        assert_eq!(r.err.as_deref(), Some("unsupported file format"));
    }

    #[test]
    fn encrypted_ole_reports_err() {
        let r = extract(&[0xD0, 0xCF, 0x11, 0xE0, 0, 0, 0, 0], Config::default());
        assert_eq!(r.err.as_deref(), Some("encrypted or legacy office format (cannot read locally)"));
    }

    #[test]
    fn size_gate_on_plaintext_yields_partial_head_tail() {
        let data = vec![b'a'; 1000];
        let cfg = Config {
            max_file_bytes: Some(100),
            head_tail_window: Some(10),
            ..Default::default()
        };
        let r = extract(&data, cfg);
        assert!(r.partial);
        assert!(r.text.contains("size gate"));
        assert!(r.text.starts_with("aaaaaaaaaa"));
        assert!(r.text.ends_with("aaaaaaaaaa"));
    }

    #[test]
    fn max_bytes_truncates() {
        let data = vec![b'x'; 1000];
        let cfg = Config {
            max_bytes: Some(50),
            ..Default::default()
        };
        let r = extract(&data, cfg);
        assert!(r.truncated);
        assert_eq!(r.text.len(), 50);
    }

    #[test]
    fn decode_entities_single_pass_no_rescan() {
        // "&amp;lt;" should decode one level to "&lt;", not all the way to "<".
        assert_eq!(decode_xml_entities("&amp;lt;"), "&lt;");
        assert_eq!(decode_xml_entities("plain &amp; text"), "plain & text");
    }

    #[test]
    fn real_docx_fixture_extracts_text() {
        let r = extract(&fixture("clean.docx"), Config::default());
        assert_eq!(r.format_type, Type::Docx);
        assert!(r.err.is_none(), "err: {:?}", r.err);
        assert!(!r.text.trim().is_empty());
    }

    #[test]
    fn real_pptx_fixture_extracts_text() {
        let r = extract(&fixture("financial.pptx"), Config::default());
        assert_eq!(r.format_type, Type::Pptx);
        assert!(r.err.is_none(), "err: {:?}", r.err);
        assert!(!r.text.trim().is_empty());
    }

    #[test]
    fn real_xlsx_fixture_extracts_text() {
        let r = extract(&fixture("pci.xlsx"), Config::default());
        assert_eq!(r.format_type, Type::Xlsx);
        assert!(r.err.is_none(), "err: {:?}", r.err);
        assert!(!r.text.trim().is_empty());
    }

    #[test]
    fn real_pdf_fixture_extracts_text() {
        let r = extract(&fixture("pii.pdf"), Config::default());
        assert_eq!(r.format_type, Type::Pdf);
        assert!(r.err.is_none(), "err: {:?}", r.err);
        assert!(!r.text.trim().is_empty());
    }

    #[test]
    fn footer_marked_docx_extracts_footer_text() {
        // word/footer* is part of the extracted set; confirms the glob-suffix match works.
        let r = extract(&fixture("footer_marked.docx"), Config::default());
        assert!(r.err.is_none(), "err: {:?}", r.err);
        assert!(!r.text.trim().is_empty());
    }
}
