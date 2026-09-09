# Why this crate is vendored, and what's patched

`pdf-extract` 0.9.0 from crates.io, vendored here with three patches applied. Wired in via
`../../Cargo.toml`'s `[patch.crates-io]` section, which replaces every use of the registry
`pdf-extract` crate across the whole workspace with this copy — no call-site changes needed
anywhere else in the codebase.

## The bug that started this

Found 2026-09 via `--cpu-soak` (see `rust/cli/src/soak.rs`), which runs the engine warm and
in-process — the shape a real embedding (`ch-inspect-ffi`) has, unlike `--scan --isolate`'s
fresh-process-per-file dev tooling. A legitimate, non-malicious 5.8MB real-world PDF
(`Bank_Account_Number/Matches/SampleFile_Ecuador_BAN_001.pdf` in the Nucleuz corpus — external,
not vendored in this repo) drove peak RSS to **587MB**.

This is a *different* problem from the already-known/mitigated "malformed PDF OOMs to multi-GB"
bomb-file class documented in `../../../DECISIONS.md` (mitigated by `--scan --isolate`'s per-file
process isolation — a bomb only kills its own child). The real production embedding path has no
equivalent of that isolation — it runs in-process, warm, inside whatever host embeds it.

## Three fixes, found in this order, only the third was the main driver

**1. `Do` never checked `/Subtype` before recursing.** `process_stream`'s `"Do"` operator handler
recursively parses a referenced XObject's content as PDF drawing commands unconditionally, for
both `/Form` (correct) and `/Image` (raw JPEG bytes, not syntax) XObjects. Confirmed via
instrumentation: 37 of 619 `Do` invocations on the trigger file were images being mis-parsed.
Fixed by checking `/Subtype` and skipping recursion for `/Image`. Spec-correct: only `/Form`
XObjects can contain nested content per the PDF spec.

**2. No memoization of repeated Forms or fonts.** The same Form gets re-extracted, and the same
font gets rebuilt via `make_font`, every time either is referenced — even when referenced dozens
of times (this file has 607 distinct Form/Image objects, mostly a handful of real fonts reused
across them). Added a `Processor`-level `visited_xobjects: HashSet<ObjectId>` and an
`ObjectId`-keyed `font_cache`. Spec-correct: neither a Form's content nor a font's metrics change
based on how many times they're referenced.

**3. The actual main driver: `"f*"`/`"s"`/`"B"`/`"B*"`/`"b"` never cleared the accumulated path.**
`process_stream` builds a `path: Path { ops: Vec<PathOp> }` as it processes path-construction
operators (`m`/`l`/`c`/`h`/`re`), and correctly clears it after painting — but only for `"S"`
(stroke), `"F"`/`"f"` (fill), and `"n"` (no-op paint). The even-odd fill (`"f*"`) and the
close/fill+stroke compound operators (`"s"`, `"B"`, `"B*"`, `"b"`) were dispatched to a branch
that did nothing at all — no `output.fill()`/`stroke()` call, and critically, **no
`path.ops.clear()`**. `"f*"` is not an obscure operator; it's one of the two standard PDF fill
rules. On the trigger file, one page alone issues 83,420 `"f*"` calls interleaved with 446,041
cumulative path-construction ops (`m`/`l`/`c`/`h`) — since the path was never cleared, all of them
stay live in one `Vec<PathOp>` for the rest of that page's content stream, instead of just one
shape's worth at a time. Fixed by giving `"f*"`/`"s"`/`"B"`/`"B*"`/`"b"` the same
fill-or-stroke-then-clear treatment `"S"`/`"F"`/`"f"` already got. (This crate's
`OutputDev::fill`/`stroke` take no fill-rule parameter, so `"f"` and `"f*"` were already
indistinguishable in the existing code for anything downstream — this isn't a new behavioural
gap, just a missing clear.)

**Confirmed present upstream through 0.12.0** (the latest release on crates.io as of this
writing) — the `Do` handler and the `"f*"`/`"s"`/`"B"`/`"B*"`/`"b"` dispatch are both
byte-for-byte identical to 0.9.0's. Bumping the pin does not fix any of this.

## What this did — and didn't — resolve

All three fixes are real, spec-correct, instrumentation-verified, and zero-downside regardless of
this specific file. Measured on the trigger file: peak RSS **587MB → 561MB** (~4.4% reduction) —
real, but far short of a full fix.

**The remaining ~561MB is not a bug in the classic sense — it's `lopdf`'s parser design meeting a
genuinely extreme document.** `Content::decode` (in `lopdf`, one layer below `pdf-extract`) uses
`nom`'s `many0` combinator to eagerly parse an *entire* content stream into one `Vec<Operation>`
before `process_stream` gets to touch any of it — each `Operation` holding its own heap-allocated
operator `String` and a separately heap-allocated `operands: Vec<Object>`. Confirmed via a
per-page operator-count dump: this file's pages 5 and 6 each contain **~604,000 real,
valid** operations — 238,504 of them `"c"` (curveto) alone. That's not misparsed garbage (ruled
out explicitly: the operator breakdown is `c`/`m`/`h`/`f*`/`rg`/`l` — all legitimate path/fill/color
operators, nothing resembling binary noise) — it's an unusually extreme, but completely valid,
vector-graphics-heavy page (plausibly a vectorized image or a dense repeating pattern/watermark).
Materializing ~604,000 real `Operation` structs with their nested per-operation `Vec<Object>`
allocations costs real, proportional memory *before painting fix #3 even gets a chance to help* —
that upfront materialization is what the remaining ~561MB is.

Closing that fully would mean rewriting `lopdf`'s content-stream parser to stream/iterate lazily
instead of building one `Vec<Operation>` up front — a much larger change than a vendor patch, and
out of scope here. **Not implemented, deliberately, rather than rushed:** a pre-flight cap on raw
content-stream byte size (skip parsing/extraction for any individual stream above some threshold,
reporting partial coverage instead) would bound the worst case without the full rewrite, but
picking a defensible threshold needs more than one data point — flagging as the next concrete
candidate rather than picking an arbitrary number now.

## How this was found

Two custom-allocator diagnostics were tried; know the difference before writing a third:
- A `Mutex<HashMap<..>>`-based one (tallying allocation sizes) **segfaulted the target process**.
  Taking a lock inside `GlobalAlloc::alloc`/`dealloc` is inherently reentrancy-risky (the mutex
  implementation, or backtrace capture, can itself allocate) — don't do this.
- A lock-free one (atomics + a thread-local re-entrancy guard, no heap-allocating state of its
  own) run against a **debug build** (release strips symbols, making backtraces useless) safely
  produced a real, symbolized backtrace pointing straight at `Content::decode` — this is what
  actually found fix #3's location. If you need to do this again: no `Mutex`, no `HashMap`, no
  other allocation inside the hook; debug build only, for the symbols.
- `dtrace` allocation tracing would likely have been faster and more precise, but needs `sudo`
  (System Integrity Protection blocks it otherwise), which wasn't available in this session.
  Instruments/`xctrace` wasn't installed either (only command-line tools, not full Xcode).
  `heaptrack`/`valgrind --tool=massif` aren't available on macOS at all — either would work on
  Linux if this needs revisiting with real tooling instead of hand-rolled allocators.

## If you're re-syncing with a newer upstream pdf-extract release

1. Check whether the new release has fixed any of these three itself (search `src/lib.rs` for the
   `"Do"` arm and the `"f*"`/`"s"`/`"B"`/`"B*"`/`"b"` dispatch in `process_stream`). As of 0.12.0
   (checked 2026-09), none were fixed — byte-for-byte identical to 0.9.0 in all three spots.
2. If not, re-apply all three patches (search `ENDPOINT-CI PATCH` comments in this version's
   `src/lib.rs` for the exact diffs) to the new version, update this directory's `Cargo.toml`
   version to match, and rebuild.
3. Re-run `--cpu-soak` (or at minimum `/usr/bin/time -l ... --file <the file above>`, if you have
   access to the external Nucleuz corpus) — the baseline with all three patches applied is
   ~561MB on that specific file, not near-zero, so "still high" doesn't mean your re-sync failed.
