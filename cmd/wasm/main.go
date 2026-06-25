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

// chInspect(name, Uint8Array) -> Promise<verdict JSON>.
//
// Returns a Promise and does the work on a goroutine: while inspection runs, the
// JS event loop stays live, so any blocking syscall the engine/deps make (e.g. a
// PDF library writing to stdout) can complete instead of deadlocking the
// single-threaded WASM scheduler.
func inspect(_ js.Value, args []js.Value) any {
	resolveErr := func(msg string) any {
		return js.Global().Get("Promise").Call("resolve", `{"verdict":"ESCALATE","error":"`+msg+`"}`)
	}
	if db == nil {
		return resolveErr("rules not loaded; call chLoadRules first")
	}
	if len(args) < 2 {
		return resolveErr("expected (name, Uint8Array)")
	}
	name := args[0].String()
	buf := make([]byte, args[1].Get("length").Int())
	js.CopyBytesToGo(buf, args[1])

	var executor js.Func
	executor = js.FuncOf(func(_ js.Value, p []js.Value) any {
		resolve := p[0]
		go func() {
			defer executor.Release()
			defer func() {
				if r := recover(); r != nil {
					resolve.Invoke(`{"verdict":"ESCALATE","error":"panic during inspect"}`)
				}
			}()
			v := engine.InspectData(name, buf, db, extract.Config{})
			out, err := json.Marshal(v)
			if err != nil {
				resolve.Invoke(`{"verdict":"ESCALATE","error":"marshal failed"}`)
				return
			}
			resolve.Invoke(string(out))
		}()
		return nil
	})
	return js.Global().Get("Promise").New(executor)
}

func main() {
	js.Global().Set("chLoadRules", js.FuncOf(loadRules))
	js.Global().Set("chInspect", js.FuncOf(inspect))
	js.Global().Get("console").Call("log", "endpoint-ci wasm ready")
	select {} // keep the Go runtime alive for callbacks
}
