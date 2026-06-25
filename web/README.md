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
  - `chInspect(name, Uint8Array)` → **`Promise`**<verdict JSON> (async, so the JS
    event loop stays live while the engine runs — required in WASM)
- The engine runs inside `worker.js` (a **Web Worker**). The page (`index.html`)
  posts each file to the worker with a timeout; if the worker doesn't answer in time
  (a hang or a memory-bomb file), the page **terminates the worker** — the browser
  reclaims its memory — marks the file `ESCALATE` (isolated), and **respawns** a
  fresh worker. This is the in-browser equivalent of the CLI's per-file process
  isolation.
- `build.sh` stages `config/rules.json` + lexicons next to the page; the worker
  fetches them and calls `chLoadRules`, then `chInspect` per file.
- The core engine is unchanged — `rules.LoadBytes` and `engine.InspectData` are the
  filesystem-free entrypoints the WASM layer calls.

Build output (`ch.wasm`, `wasm_exec.js`, `config/`) is git-ignored; regenerate with
`build.sh`. Headless sanity check (no browser): see the Node snippet referenced in
the commit, or just open the page.

## Verified

Two runs against the Nucleuz policy test corpus through the WASM build (headless
Node harnesses mirroring the browser model):

1. **Logic parity (non-PDF, 2,276 files):** verdicts **2,276 / 2,276 identical to
   native** — the WASM build is logically the same engine.
2. **Full corpus incl. all PDFs (3,733 files), via the Web-Worker isolation model:**
   completed in ~142 s; the **24 memory-bomb PDFs were isolated** (terminated on a
   1.5 s timeout + worker respawned) instead of OOM-crashing the run; verdict parity
   **3,722 / 3,733 (99.7%)**. The 11 differences are slow PDFs the tight 1.5 s worker
   timeout isolated but native finished at its 8 s limit — a timeout-policy
   difference, not a logic one.

WASM latency: p50 ~3 ms, p95 ~28 ms (≈3–5× native — single-threaded, no parallel
scan; still interactive).

## Production notes

- The **Web Worker is the isolation boundary** (implemented in `worker.js` +
  `index.html`). Tune the timeout for your environment; the size gate still bounds
  large files, and you may also cap/disable PDF in-page for stricter safety.
- WASM is single-threaded (`NumCPU`→1), so the parallel scan doesn't speed up —
  fine, files are small (a few ms each).
- `ledongthuc/pdf` prints an unconditional `DEBUG:` line on some malformed PDFs; in
  WASM that surfaces as harmless `console.log` noise (the async `chInspect` keeps it
  from deadlocking).
- Rules are loaded from JS (fetched), so they stay external and tunable — the same
  decoupling that lets the endpoint build hot-swap rule bundles.
