// Package label detects sensitivity / classification labels (spec §4.5).
//
// The metadata fast-path opens an OOXML container and reads ONLY the document
// property parts (docProps/custom.xml, core.xml) — no full text extraction — and
// matches property names against marker metadata-properties and property values
// against marker label strings. Metadata labels are machine-written, so they are
// high-confidence. A body fallback scans already-extracted text for label strings
// (lower confidence).
package label

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"strings"

	"github.com/cyberhaven/endpoint-ci/internal/format"
	"github.com/cyberhaven/endpoint-ci/internal/rules"
)

const (
	SourceMetadata = "metadata"
	SourceBody     = "body"
)

type Match struct {
	MarkerID string `json:"marker_id"`
	Label    string `json:"label"`
	Source   string `json:"source"`
	Property string `json:"property,omitempty"`
}

// metaParts are the OOXML property parts read by the fast-path (no body extraction).
var metaParts = []string{"docProps/custom.xml", "docProps/core.xml"}

// Metadata runs the fast-path over the raw container bytes: OOXML docProps or a
// PDF XMP packet. Returns nil for other formats.
func Metadata(data []byte, ft format.Type, markers []rules.LabelMarker) []Match {
	switch ft {
	case format.PDF:
		return xmp(data, markers)
	case format.DOCX, format.XLSX, format.PPTX:
	default:
		return nil
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}
	var out []Match
	seen := map[string]bool{}
	for _, f := range zr.File {
		if !contains(metaParts, f.Name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(rc, 1<<20))
		rc.Close()
		for _, m := range scanProps(raw, markers) {
			key := m.MarkerID + "|" + m.Property + "|" + m.Label
			if !seen[key] {
				seen[key] = true
				out = append(out, m)
			}
		}
	}
	return out
}

// scanProps decodes <property name="..."> name + inner value pairs and matches
// names against metadata-properties and values against label strings. Also
// matches free chardata (core.xml keywords/category) against label strings.
func scanProps(raw []byte, markers []rules.LabelMarker) []Match {
	var out []Match
	dec := xml.NewDecoder(bytes.NewReader(raw))
	var curProp string // active <property name=...>
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			curProp = ""
			for _, a := range t.Attr {
				if a.Name.Local == "name" {
					curProp = a.Value
				}
			}
			if curProp != "" {
				for _, mk := range markers {
					for _, mp := range mk.MetadataProperties {
						if strings.Contains(curProp, mp) {
							out = append(out, Match{MarkerID: mk.ID, Label: curProp,
								Source: SourceMetadata, Property: mp})
						}
					}
				}
			}
		case xml.CharData:
			val := strings.TrimSpace(string(t))
			if val == "" {
				continue
			}
			lv := strings.ToLower(val)
			for _, mk := range markers {
				for _, s := range mk.Strings {
					if strings.Contains(lv, strings.ToLower(s)) {
						out = append(out, Match{MarkerID: mk.ID, Label: val,
							Source: SourceMetadata, Property: curProp})
					}
				}
			}
		case xml.EndElement:
			curProp = ""
		}
	}
	return out
}

// xmp matches a PDF's XMP metadata packet (the analogue of OOXML docProps).
// MSIP/AIP labels live there as custom properties; classification can appear in
// dc:/pdf:/custom schema. We locate the (usually uncompressed) xpacket and match
// property names (normalised, so "msip:Label" matches the "MSIP_Label" cue) and
// label-string values. Compressed metadata streams are not handled (documented).
func xmp(data []byte, markers []rules.LabelMarker) []Match {
	pkt := extractXMP(data)
	if pkt == "" {
		return nil
	}
	low := strings.ToLower(pkt)
	norm := normAlnum(pkt)
	var out []Match
	seen := map[string]bool{}
	add := func(m Match) {
		k := m.MarkerID + "|" + m.Property + "|" + m.Label
		if !seen[k] {
			seen[k] = true
			out = append(out, m)
		}
	}
	for _, mk := range markers {
		for _, mp := range mk.MetadataProperties {
			if strings.Contains(norm, normAlnum(mp)) {
				add(Match{MarkerID: mk.ID, Label: mp, Source: SourceMetadata, Property: mp})
			}
		}
		for _, s := range mk.Strings {
			if strings.Contains(low, strings.ToLower(s)) {
				add(Match{MarkerID: mk.ID, Label: s, Source: SourceMetadata})
			}
		}
	}
	return out
}

// extractXMP returns the XMP packet text from raw PDF bytes, or "".
func extractXMP(data []byte) string {
	start := bytes.Index(data, []byte("<?xpacket begin"))
	if start < 0 {
		start = bytes.Index(data, []byte("<x:xmpmeta"))
	}
	if start < 0 {
		return ""
	}
	if e := bytes.Index(data[start:], []byte("<?xpacket end")); e >= 0 {
		tail := start + e
		if pe := bytes.IndexByte(data[tail:], '>'); pe >= 0 {
			return string(data[start : tail+pe+1])
		}
		return string(data[start:tail])
	}
	if m := bytes.Index(data[start:], []byte("</x:xmpmeta>")); m >= 0 {
		return string(data[start : start+m+len("</x:xmpmeta>")])
	}
	end := start + (1 << 20)
	if end > len(data) {
		end = len(data)
	}
	return string(data[start:end])
}

// normAlnum lowercases and drops non-alphanumerics, so separators/case differ-
// ences between cues ("MSIP_Label") and XMP element names ("msip:Label") match.
func normAlnum(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Body scans extracted text for label strings (lower-confidence fallback). To
// avoid flagging the word "Confidential" in ordinary prose, it only considers
// *distinctive* markings — multi-word or all-caps — and matches case-sensitively.
func Body(text string, markers []rules.LabelMarker) []Match {
	var out []Match
	seen := map[string]bool{}
	for _, mk := range markers {
		for _, s := range mk.Strings {
			if !distinctive(s) {
				continue
			}
			if strings.Contains(text, s) {
				key := mk.ID + "|" + s
				if !seen[key] {
					seen[key] = true
					out = append(out, Match{MarkerID: mk.ID, Label: s, Source: SourceBody})
				}
			}
		}
	}
	return out
}

func distinctive(s string) bool {
	return strings.Contains(s, " ") || s == strings.ToUpper(s)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
