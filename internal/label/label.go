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

// Metadata runs the fast-path over the raw OOXML bytes. Returns nil for non-OOXML.
func Metadata(data []byte, ft format.Type, markers []rules.LabelMarker) []Match {
	switch ft {
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
