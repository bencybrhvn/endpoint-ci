# Browser / WASM demo

The inspection engine compiled to WebAssembly — a proof that the same Go code can
run in a browser extension. Files are inspected **entirely in the page**; nothing
is uploaded.

## Run it

```bash
./web/build.sh                       # compiles ch.wasm + stages runtime & rules
cd web && python3 -m http.server 8080
# open http://localhost:8080/
```

A static server is required — `fetch()` + `WebAssembly.instantiateStreaming` don't
work over `file://`. Then drop a file (txt/csv/docx/xlsx/pptx/pdf) or paste text;
you get the verdict, profiles, labels, and scan time.

## How it works

- `cmd/wasm/main.go` (`//go:build js && wasm`) exposes two functions to JS via
  `syscall/js`:
  - `chLoadRules(rulesJSON, givenNames, surnames, commonWords)` → `{detectors, profiles}`
  - `chInspect(name, Uint8Array)` → verdict JSON
- `build.sh` stages `config/rules.json` + lexicons next to the page; `index.html`
  fetches them and calls `chLoadRules`, then `chInspect` per file.
- The core engine is unchanged — `rules.LoadBytes` and `engine.InspectData` are the
  filesystem-free entrypoints the WASM layer calls.

Build output (`ch.wasm`, `wasm_exec.js`, `config/`) is git-ignored; regenerate with
`build.sh`. Headless sanity check (no browser): see the Node snippet referenced in
the commit, or just open the page.

## Production notes

- **Run the WASM in a Web Worker** and terminate it on a timeout. A malicious PDF
  can drive the pure-Go PDF parser to high memory — in the browser the worker is the
  isolation boundary (the equivalent of the per-file process isolation used by the
  CLI `--scan`). Enforce the size gate and consider capping/disabling PDF in-page.
- WASM is single-threaded here (`NumCPU`→1), so the parallel scan doesn't speed up —
  fine, files are small (sub-millisecond to a few ms each).
- Rules are loaded from JS (fetched), so they stay external and tunable — the same
  decoupling that lets the endpoint build hot-swap rule bundles.
