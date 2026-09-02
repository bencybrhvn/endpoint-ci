//! Detects sensitivity / classification labels (spec §4.5). Ported from
//! `internal/label/label.go`.
//!
//! The metadata fast-path opens an OOXML container and reads ONLY the document property parts
//! (`docProps/custom.xml`, `core.xml`) — no full text extraction — and matches property names
//! against marker metadata-properties and property values against marker label strings.
//! Metadata labels are machine-written, so they are high-confidence. A body fallback scans
//! already-extracted text for label strings (lower confidence).

use std::collections::HashSet;
use std::io::{Cursor, Read};

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

use crate::format::Type;
use crate::rules::LabelMarker;

pub const SOURCE_METADATA: &str = "metadata";
pub const SOURCE_BODY: &str = "body";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Match {
    pub marker_id: String,
    pub label: String,
    pub source: String,
    /// `None` where Go leaves `Property` as the empty string (its `omitempty` counterpart).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property: Option<String>,
}

/// The OOXML property parts read by the fast-path (no body extraction).
const META_PARTS: &[&str] = &["docProps/custom.xml", "docProps/core.xml"];

/// Runs the fast-path over the raw container bytes: OOXML docProps or a PDF XMP packet.
/// Returns an empty vec for other formats.
pub fn metadata(data: &[u8], ft: Type, markers: &[LabelMarker]) -> Vec<Match> {
    match ft {
        Type::Pdf => return xmp(data, markers),
        Type::Docx | Type::Xlsx | Type::Pptx => {}
        _ => return Vec::new(),
    }
    let Ok(mut zr) = zip::ZipArchive::new(Cursor::new(data)) else {
        return Vec::new();
    };
    let names: Vec<String> = zr.file_names().map(str::to_string).collect();

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for name in names {
        if !META_PARTS.contains(&name.as_str()) {
            continue;
        }
        let Ok(mut file) = zr.by_name(&name) else { continue };
        let mut raw = Vec::new();
        if file.by_ref().take(1 << 20).read_to_end(&mut raw).is_err() {
            continue;
        }
        for m in scan_props(&raw, markers) {
            let key = format!("{}|{}|{}", m.marker_id, m.property.as_deref().unwrap_or(""), m.label);
            if seen.insert(key) {
                out.push(m);
            }
        }
    }
    out
}

/// Decodes `<property name="...">` name + inner value pairs and matches names against
/// metadata-properties and values against label strings. Also matches free chardata (core.xml
/// keywords/category) against label strings.
fn scan_props(raw: &[u8], markers: &[LabelMarker]) -> Vec<Match> {
    let mut out = Vec::new();
    let mut reader = Reader::from_reader(raw);
    let mut cur_prop = String::new();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) | Err(_) => break, // Go's decoder likewise just stops on any error
            Ok(Event::Start(e)) => cur_prop = start_element(&e, markers, &mut out),
            Ok(Event::Empty(e)) => {
                start_element(&e, markers, &mut out);
                cur_prop.clear();
            }
            Ok(Event::Text(t)) => {
                if let Ok(text) = t.unescape() {
                    char_data(&text, &cur_prop, markers, &mut out);
                }
            }
            Ok(Event::End(_)) => cur_prop.clear(),
            _ => {}
        }
    }
    out
}

fn start_element(e: &BytesStart, markers: &[LabelMarker], out: &mut Vec<Match>) -> String {
    let mut cur_prop = String::new();
    for attr in e.attributes().flatten() {
        if attr.key.local_name().as_ref() == b"name" {
            cur_prop = String::from_utf8_lossy(&attr.value).into_owned();
        }
    }
    if !cur_prop.is_empty() {
        for mk in markers {
            for mp in &mk.metadata_properties {
                if cur_prop.contains(mp.as_str()) {
                    out.push(Match {
                        marker_id: mk.id.clone(),
                        label: cur_prop.clone(),
                        source: SOURCE_METADATA.to_string(),
                        property: Some(mp.clone()),
                    });
                }
            }
        }
    }
    cur_prop
}

fn char_data(text: &str, cur_prop: &str, markers: &[LabelMarker], out: &mut Vec<Match>) {
    let val = text.trim();
    if val.is_empty() {
        return;
    }
    let lv = val.to_lowercase();
    for mk in markers {
        for s in &mk.strings {
            if lv.contains(&s.to_lowercase()) {
                out.push(Match {
                    marker_id: mk.id.clone(),
                    label: val.to_string(),
                    source: SOURCE_METADATA.to_string(),
                    property: if cur_prop.is_empty() { None } else { Some(cur_prop.to_string()) },
                });
            }
        }
    }
}

/// Matches a PDF's XMP metadata packet (the analogue of OOXML docProps). MSIP/AIP labels live
/// there as custom properties; classification can appear in `dc:`/`pdf:`/custom schema. We
/// locate the (usually uncompressed) xpacket and match property names (normalised, so
/// "msip:Label" matches the "MSIP_Label" cue) and label-string values. Compressed metadata
/// streams are not handled (documented).
fn xmp(data: &[u8], markers: &[LabelMarker]) -> Vec<Match> {
    let Some(pkt) = extract_xmp(data) else { return Vec::new() };
    let low = pkt.to_lowercase();
    let norm = norm_alnum(&pkt);
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut add = |m: Match| {
        let key = format!("{}|{}|{}", m.marker_id, m.property.as_deref().unwrap_or(""), m.label);
        if seen.insert(key) {
            out.push(m);
        }
    };
    for mk in markers {
        for mp in &mk.metadata_properties {
            if norm.contains(&norm_alnum(mp)) {
                add(Match {
                    marker_id: mk.id.clone(),
                    label: mp.clone(),
                    source: SOURCE_METADATA.to_string(),
                    property: Some(mp.clone()),
                });
            }
        }
        for s in &mk.strings {
            if low.contains(&s.to_lowercase()) {
                add(Match {
                    marker_id: mk.id.clone(),
                    label: s.clone(),
                    source: SOURCE_METADATA.to_string(),
                    property: None,
                });
            }
        }
    }
    out
}

/// Returns the XMP packet text from raw PDF bytes, or `None`.
fn extract_xmp(data: &[u8]) -> Option<String> {
    let start = memchr::memmem::find(data, b"<?xpacket begin").or_else(|| memchr::memmem::find(data, b"<x:xmpmeta"))?;
    if let Some(e) = memchr::memmem::find(&data[start..], b"<?xpacket end") {
        let tail = start + e;
        if let Some(pe) = data[tail..].iter().position(|&b| b == b'>') {
            return Some(String::from_utf8_lossy(&data[start..tail + pe + 1]).into_owned());
        }
        return Some(String::from_utf8_lossy(&data[start..tail]).into_owned());
    }
    if let Some(m) = memchr::memmem::find(&data[start..], b"</x:xmpmeta>") {
        return Some(String::from_utf8_lossy(&data[start..start + m + "</x:xmpmeta>".len()]).into_owned());
    }
    let end = (start + (1 << 20)).min(data.len());
    Some(String::from_utf8_lossy(&data[start..end]).into_owned())
}

/// Lowercases and drops non-alphanumerics, so separator/case differences between cues
/// ("MSIP_Label") and XMP element names ("msip:Label") match.
fn norm_alnum(s: &str) -> String {
    s.to_lowercase().chars().filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit()).collect()
}

/// Scans extracted text for label strings (lower-confidence fallback). To avoid flagging the
/// word "Confidential" in ordinary prose, it only considers *distinctive* markings —
/// multi-word or all-caps — and matches case-sensitively.
pub fn body(text: &str, markers: &[LabelMarker]) -> Vec<Match> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for mk in markers {
        for s in &mk.strings {
            if !distinctive(s) {
                continue;
            }
            if text.contains(s.as_str()) {
                let key = format!("{}|{s}", mk.id);
                if seen.insert(key) {
                    out.push(Match {
                        marker_id: mk.id.clone(),
                        label: s.clone(),
                        source: SOURCE_BODY.to_string(),
                        property: None,
                    });
                }
            }
        }
    }
    out
}

fn distinctive(s: &str) -> bool {
    s.contains(' ') || s == s.to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture(name: &str) -> Vec<u8> {
        let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/docs")).join(name);
        std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {path:?}: {e}"))
    }

    fn real_markers() -> Vec<LabelMarker> {
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
        let raw = std::fs::read(root.join("config/rules.json")).expect("read config/rules.json");
        let db: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        serde_json::from_value(db["label_markers"].clone()).unwrap()
    }

    #[test]
    fn labeled_docx_fires_metadata_match() {
        let markers = real_markers();
        let matches = metadata(&fixture("labeled.docx"), Type::Docx, &markers);
        assert!(!matches.is_empty(), "expected at least one metadata label match");
        assert!(matches.iter().all(|m| m.source == SOURCE_METADATA));
    }

    #[test]
    fn clean_docx_has_no_metadata_match() {
        let markers = real_markers();
        let matches = metadata(&fixture("clean.docx"), Type::Docx, &markers);
        assert!(matches.is_empty(), "expected no label matches on a clean file: {matches:?}");
    }

    #[test]
    fn labeled_pdf_fires_xmp_match() {
        let markers = real_markers();
        let matches = metadata(&fixture("labeled.pdf"), Type::Pdf, &markers);
        assert!(!matches.is_empty(), "expected at least one XMP label match");
    }

    #[test]
    fn other_formats_return_empty() {
        let markers = real_markers();
        assert!(metadata(b"plain text, not a container", Type::Plaintext, &markers).is_empty());
    }

    #[test]
    fn body_matches_distinctive_markings_only() {
        let markers = real_markers();
        // "COMPANY CONFIDENTIAL" is all-caps and multi-word => distinctive; a stray lowercase
        // "confidential" mention should not, on its own, trip anything.
        let text = "This memo is marked COMPANY CONFIDENTIAL. Please treat it as such.";
        let matches = body(text, &markers);
        assert!(matches.iter().any(|m| m.label == "COMPANY CONFIDENTIAL"));

        let plain = "This is a confidential sounding sentence with no real marking in it.";
        let plain_matches = body(plain, &markers);
        assert!(
            plain_matches.is_empty(),
            "bare lowercase word should not trigger a body match: {plain_matches:?}"
        );
    }
}
