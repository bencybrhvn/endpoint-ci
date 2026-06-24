// Package extract turns a file's bytes into inspectable plain text per format:
// plaintext direct, OOXML via archive/zip + tag stripping, PDF text layer via
// ledongthuc/pdf. Extraction failures degrade gracefully (Err set, never panic).
package extract

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/cyberhaven/endpoint-ci/internal/format"
	"github.com/ledongthuc/pdf"
)

type Config struct {
	MaxBytes int // cap on extracted text (default 5 MB)
}

type Result struct {
	Type      format.Type
	Text      string
	Truncated bool
	Err       string // non-empty on extraction failure
}

const defaultMaxBytes = 5 << 20

// Extract detects the format of data and returns its inspectable text.
func Extract(data []byte, cfg Config) Result {
	max := cfg.MaxBytes
	if max == 0 {
		max = defaultMaxBytes
	}
	t := format.Detect(data)
	r := Result{Type: t}

	switch t {
	case format.Plaintext:
		r.Text = string(data)
	case format.DOCX, format.XLSX, format.PPTX:
		txt, err := extractOOXML(data, t)
		if err != nil {
			r.Err = err.Error()
			return r
		}
		r.Text = txt
	case format.PDF:
		txt, err := extractPDF(data)
		if err != nil {
			r.Err = err.Error()
			return r
		}
		r.Text = txt
	case format.Encrypted:
		r.Err = "encrypted or legacy office format (cannot read locally)"
		return r
	default:
		r.Err = "unsupported file format"
		return r
	}

	if len(r.Text) > max {
		r.Text = r.Text[:max]
		r.Truncated = true
	}
	return r
}

// --- OOXML ---

// ooxmlParts lists the zip entries that carry user text per OOXML type. Glob is
// a simple prefix/suffix match (prefix*, *suffix, or exact).
var ooxmlParts = map[format.Type][]string{
	format.DOCX: {"word/document.xml", "word/header*", "word/footer*", "docProps/core.xml", "docProps/custom.xml"},
	format.XLSX: {"xl/sharedStrings.xml", "docProps/core.xml", "docProps/custom.xml"},
	format.PPTX: {"ppt/slides/slide*", "docProps/core.xml", "docProps/custom.xml"},
}

func extractOOXML(data []byte, t format.Type) (string, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("open ooxml: %w", err)
	}
	patterns := ooxmlParts[t]
	// stable order for deterministic output
	files := make([]*zip.File, len(zr.File))
	copy(files, zr.File)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })

	var sb strings.Builder
	for _, f := range files {
		if !matchAny(f.Name, patterns) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue // skip unreadable part, don't fail whole file
		}
		raw, err := io.ReadAll(io.LimitReader(rc, defaultMaxBytes))
		rc.Close()
		if err != nil {
			continue
		}
		sb.WriteString(stripXML(raw))
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

func matchAny(name string, patterns []string) bool {
	for _, p := range patterns {
		switch {
		case strings.HasSuffix(p, "*"):
			if strings.HasPrefix(name, p[:len(p)-1]) {
				return true
			}
		case name == p:
			return true
		}
	}
	return false
}

// stripXML drops tags and returns text, inserting a space at each tag boundary
// so adjacent runs don't fuse. Decodes the common XML entities.
func stripXML(raw []byte) string {
	var sb strings.Builder
	inTag := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '<':
			inTag = true
			sb.WriteByte(' ')
		case c == '>':
			inTag = false
		case !inTag:
			sb.WriteByte(c)
		}
	}
	s := sb.String()
	repl := strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", "\"", "&apos;", "'")
	return repl.Replace(s)
}

// --- PDF (text layer) ---

func extractPDF(data []byte) (text string, err error) {
	// ledongthuc/pdf can panic on malformed PDFs; recover into an error.
	defer func() {
		if r := recover(); r != nil {
			text, err = "", fmt.Errorf("pdf parse panic: %v", r)
		}
	}()
	r, err := pdf.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("open pdf: %w", err)
	}
	rd, err := r.GetPlainText()
	if err != nil {
		return "", fmt.Errorf("pdf text: %w", err)
	}
	var sb strings.Builder
	if _, err := io.Copy(&sb, rd); err != nil {
		return "", fmt.Errorf("pdf read: %w", err)
	}
	return sb.String(), nil
}
