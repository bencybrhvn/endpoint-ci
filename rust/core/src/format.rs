//! Detects a file's type from magic bytes / container contents. Ported from
//! `internal/format/format.go`.

use std::io::Cursor;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Type {
    #[default]
    Unknown,
    Plaintext,
    Docx,
    Xlsx,
    Pptx,
    Pdf,
    /// OLE compound file: legacy office or password-protected.
    Encrypted,
    Unsupported,
}

impl Type {
    pub fn as_str(&self) -> &'static str {
        match self {
            Type::Plaintext => "plaintext",
            Type::Docx => "docx",
            Type::Xlsx => "xlsx",
            Type::Pptx => "pptx",
            Type::Pdf => "pdf",
            Type::Encrypted => "encrypted",
            Type::Unsupported => "unsupported",
            Type::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classifies data by leading magic bytes, inspecting ZIP entries for OOXML.
pub fn detect(data: &[u8]) -> Type {
    if data.starts_with(b"%PDF") {
        return Type::Pdf;
    }
    if data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0]) {
        return Type::Encrypted; // OLE2: legacy .doc/.xls or encrypted OOXML.
    }
    if data.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
        return ooxml_type(data);
    }
    if is_textual(data) {
        return Type::Plaintext;
    }
    Type::Unsupported
}

fn ooxml_type(data: &[u8]) -> Type {
    let reader = match zip::ZipArchive::new(Cursor::new(data)) {
        Ok(r) => r,
        Err(_) => return Type::Unsupported,
    };
    let names: Vec<&str> = reader.file_names().collect();
    if names.contains(&"word/document.xml") {
        return Type::Docx;
    }
    if names.iter().any(|n| *n == "xl/workbook.xml" || n.starts_with("xl/")) {
        return Type::Xlsx;
    }
    if names.iter().any(|n| n.starts_with("ppt/slides/")) {
        return Type::Pptx;
    }
    Type::Unsupported
}

/// Valid UTF-8 with no NUL bytes in the sampled prefix.
fn is_textual(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    let n = data.len().min(8192);
    let sample = &data[..n];
    if sample.contains(&0u8) {
        return false;
    }
    std::str::from_utf8(sample).is_ok()
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
    fn plaintext() {
        assert_eq!(detect(b"hello world"), Type::Plaintext);
        assert_eq!(detect(b""), Type::Plaintext);
    }

    #[test]
    fn binary_non_textual_is_unsupported() {
        assert_eq!(detect(&[0x01, 0x02, 0x00, 0xFF, 0xFE]), Type::Unsupported);
    }

    #[test]
    fn pdf_header() {
        assert_eq!(detect(b"%PDF-1.4\n..."), Type::Pdf);
    }

    #[test]
    fn ole_header_is_encrypted() {
        assert_eq!(detect(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]), Type::Encrypted);
    }

    #[test]
    fn real_docx_fixture() {
        assert_eq!(detect(&fixture("clean.docx")), Type::Docx);
    }

    #[test]
    fn real_pptx_fixture() {
        assert_eq!(detect(&fixture("financial.pptx")), Type::Pptx);
    }

    #[test]
    fn real_xlsx_fixture() {
        assert_eq!(detect(&fixture("pci.xlsx")), Type::Xlsx);
    }

    #[test]
    fn real_pdf_fixture() {
        assert_eq!(detect(&fixture("labeled.pdf")), Type::Pdf);
    }

    #[test]
    fn legacy_doc_fixture_is_encrypted() {
        // Legacy OLE2 .doc — same container family as password-protected OOXML, both surface
        // as "can't read this locally" rather than a distinct legacy-format type (spec scope).
        assert_eq!(detect(&fixture("legacy.doc")), Type::Encrypted);
    }
}
