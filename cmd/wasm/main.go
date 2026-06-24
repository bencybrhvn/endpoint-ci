//go:build js && wasm

// Command wasm is the browser entrypoint: it exposes the inspection engine to
// JavaScript via syscall/js. Build with:
//
//	GOOS=js GOARCH=wasm go build -o web/ch.wasm ./cmd/wasm
//
// JS API (see web/index.html):
//
//	chLoadRules(rulesJSON, givenNames, surnames, commonWords) -> {detectors, profiles} | {error}
//	chInspect(name, Uint8Array)                               -> verdict JSON string
package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/cyberhaven/endpoint-ci/internal/engine"
	"github.com/cyberhaven/endpoint-ci/internal/extract"
	"github.com/cyberhaven/endpoint-ci/internal/rules"
)

var db *rules.DB

// loadRules(rulesJSON, givenNames, surnames, commonWords)
func loadRules(_ js.Value, args []js.Value) any {
	if len(args) < 4 {
		return map[string]any{"error": "expected (rulesJSON, givenNames, surnames, commonWords)"}
	}
	lex := map[string][]byte{
		"config/lexicons/given_names.txt":  []byte(args[1].String()),
		"config/lexicons/surnames.txt":     []byte(args[2].String()),
		"config/lexicons/common_words.txt": []byte(args[3].String()),
	}
	d, err := rules.LoadBytes([]byte(args[0].String()), lex)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	db = d
	return map[string]any{"detectors": len(d.Detectors), "profiles": len(d.Profiles)}
}

// chInspect(name, Uint8Array) -> verdict JSON
func inspect(_ js.Value, args []js.Value) any {
	if db == nil {
		return `{"error":"rules not loaded; call chLoadRules first"}`
	}
	if len(args) < 2 {
		return `{"error":"expected (name, Uint8Array)"}`
	}
	name := args[0].String()
	buf := make([]byte, args[1].Get("length").Int())
	js.CopyBytesToGo(buf, args[1])

	v := engine.InspectData(name, buf, db, extract.Config{})
	out, err := json.Marshal(v)
	if err != nil {
		return `{"error":"marshal failed"}`
	}
	return string(out)
}

func main() {
	js.Global().Set("chLoadRules", js.FuncOf(loadRules))
	js.Global().Set("chInspect", js.FuncOf(inspect))
	js.Global().Get("console").Call("log", "endpoint-ci wasm ready")
	select {} // keep the Go runtime alive for callbacks
}
