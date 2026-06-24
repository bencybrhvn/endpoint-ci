// Package format detects a file's type from magic bytes / container contents.
package format

import (
	"archive/zip"
	"bytes"
	"unicode/utf8"
)

type Type int

const (
	Unknown Type = iota
	Plaintext
	DOCX
	XLSX
	PPTX
	PDF
	Encrypted // OLE compound file: legacy office or password-protected
	Unsupported
)

func (t Type) String() string {
	switch t {
	case Plaintext:
		return "plaintext"
	case DOCX:
		return "docx"
	case XLSX:
		return "xlsx"
	case PPTX:
		return "pptx"
	case PDF:
		return "pdf"
	case Encrypted:
		return "encrypted"
	case Unsupported:
		return "unsupported"
	}
	return "unknown"
}

// Detect classifies data by leading magic bytes, inspecting ZIP entries for OOXML.
func Detect(data []byte) Type {
	if bytes.HasPrefix(data, []byte("%PDF")) {
		return PDF
	}
	if bytes.HasPrefix(data, []byte{0xD0, 0xCF, 0x11, 0xE0}) {
		return Encrypted // OLE2: legacy .doc/.xls or encrypted OOXML
	}
	if bytes.HasPrefix(data, []byte{0x50, 0x4B, 0x03, 0x04}) {
		return ooxmlType(data)
	}
	if isTextual(data) {
		return Plaintext
	}
	return Unsupported
}

func ooxmlType(data []byte) Type {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return Unsupported
	}
	has := func(name string) bool {
		for _, f := range zr.File {
			if f.Name == name {
				return true
			}
		}
		return false
	}
	hasPrefix := func(p string) bool {
		for _, f := range zr.File {
			if len(f.Name) >= len(p) && f.Name[:len(p)] == p {
				return true
			}
		}
		return false
	}
	switch {
	case has("word/document.xml"):
		return DOCX
	case has("xl/workbook.xml") || hasPrefix("xl/"):
		return XLSX
	case hasPrefix("ppt/slides/"):
		return PPTX
	}
	return Unsupported
}

// isTextual: valid UTF-8 with no NUL bytes in the sampled prefix.
func isTextual(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	n := len(data)
	if n > 8192 {
		n = 8192
	}
	sample := data[:n]
	if bytes.IndexByte(sample, 0) >= 0 {
		return false
	}
	return utf8.Valid(sample)
}
