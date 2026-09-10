# Why this crate is vendored, and what's patched

`pdf-extract` 0.9.0 from crates.io, vendored here with four patches applied. Wired in via
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

**Not country- or language-specific, despite the trigger files' names.** The two real-world files
that drove this investigation happen to be an Ecuadorian bank form and an Indian
government-form PDF, but the actual defects are generic PDF-parsing bugs triggered by *how* a PDF
was generated (dense vector graphics, heavy use of the `"f*"` fill operator, CorelDRAW-style
"convert text to curves" exports) — not by *what* country or language the content is in. The same
bugs would hit a US or UK document produced by similar generator software. Don't read "Ecuador"/
"Hindi" in this file as scoping the risk to those markets.

## Four fixes, found in this order

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

**4. Pre-flight content-stream size gate, calibrated from a real-corpus survey.** Fixes 1-3
brought the trigger file down from 587MB to 561MB — real, but nowhere near enough, because the
remaining cost isn't a bug in the classic sense: `Content::decode` (in `lopdf`, one layer below
`pdf-extract`) eagerly parses an *entire* content stream into one `Vec<Operation>` (each with its
own heap-allocated operator `String` and `operands: Vec<Object>`) *before* `process_stream` can
touch any of it. A per-page operator-count dump confirmed the trigger file's pages 5 and 6 each
contain **~604,000 real, valid** operations (238,504 `"c"`/curveto alone) — not misparsed garbage,
an unusually extreme but completely legitimate vector-graphics-heavy page. That upfront
materialization costs real, proportional memory regardless of how efficiently the operations are
processed afterward — fix #3 can't touch it, and neither can any operator-level fix.

Rather than guess a threshold, surveyed peak RSS across 200 real PDFs (60 largest-by-file-size +
140 random, from the full ~1,457-PDF Nucleuz corpus) with fixes 1-3 applied, and additionally
measured raw decompressed content-stream byte size at the exact point `Content::decode` is
called (free to check — it's already the function's own parameter). Every legitimate stream
observed topped out at **804KB**; the two pathological cases found were **2.29MB** (a second,
independently-discovered case — CorelDRAW-exported, all text converted to vector curves, no
embedded fonts at all, ~15s CPU-bound) and **15.5MB** (the original trigger). That's a clean order-
of-magnitude gap between legitimate and pathological, not a fine judgment call. Set the cap at
**2,000,000 bytes** — comfortably above every legitimate case observed (2.5x the largest), inside
the gap, catching both known-pathological streams. When a stream exceeds it, `process_stream`
returns immediately without calling `Content::decode` at all — skipping *only that one stream*
(a page or a Form), not the whole document; `begin_page`/`end_page` still fire normally around it,
so other pages keep extracting text as usual.

**Known limitation:** there's no `coverage: partial`-style signal plumbed back up through this
crate's `Result` type for a stream skipped this way — a caller can't currently distinguish "this
page had no text" from "this page was skipped for size." Not implemented, to avoid a bigger API
change for something affecting a small fraction of real files (per the survey, well under 10%
even in a sample deliberately biased toward the largest files in the corpus). Worth adding if this
starts mattering in practice.

**Confirmed present upstream through 0.12.0** (the latest release on crates.io as of this
writing) — the `Do` handler and the `"f*"`/`"s"`/`"B"`/`"B*"`/`"b"` dispatch are both
byte-for-byte identical to 0.9.0's, and there's obviously no upstream equivalent of a project-
specific calibrated size gate. Bumping the pin does not fix any of this.

## What this did — and didn't — resolve

All four fixes are real, evidence-based, and zero-downside for legitimate content (fixes 1-3 are
spec-correct; fix 4's threshold sits 2.5x above every legitimate case actually observed). Measured
on the trigger file: peak RSS **587MB → 561MB → 72MB** (fixes 1-3, then fix 4), runtime
1.34s → 0.74s. The independently-found CorelDRAW case improved from 102MB/26.35s to 82MB/14.75s —
partial, not fully resolved, because its cost is spread across *several* medium pages (583KB-
1.36MB each, mostly under the 2MB gate) rather than one giant one; a byte-size cap can't cleanly
separate "several legitimately large-ish pages" from "one pathological page" without also risking
false positives on genuinely fine content in that same size range. Deliberately not chased
further — confirmed with the project owner that this isn't a target-market document type, and the
fix already generalizes (see the note above the fixes list) to the actual risk class regardless.

**Aggregate effect across the 200-file survey, before vs. after fix 4** (fixes 1-3 already
applied in both columns):

| | Before fix 4 | After fix 4 |
|---|---|---|
| p50 / p90 / p95 / p99 | 15.9 / 38.9 / 85.4 / 142.8 MB | 16.0 / 42.4 / 76.8 / 103.3 MB |
| max | 560.3 MB | **105.2 MB** |
| files over 150MB | 2/199 (1.0%) | 0/200 (0%) |
| files over 300MB | 2/199 (1.0%) | 0/200 (0%) |

The catastrophic tail is gone (worst case dropped 5.3x, nothing exceeds 150MB in this survey
anymore). ~9% of files still exceed the strict 50MB `CLAUDE.md` budget line, mostly now in the
50-105MB range rather than hundreds of MB — a real, still-open, but much softer residual than the
one this patch set out to fix.

## Residual ~9% investigated further (2026-09-10) — no viable fifth fix, documented as a known limit

After fix 4, ~9% of the 200-file survey still exceeds the strict 50MB `CLAUDE.md` peak-RSS budget
(50-105MB range). Dug into *why*, the same evidence-before-threshold way as fix 4, rather than
guessing at a fifth fix. Conclusion: this residual isn't one bug with a clean cutoff — it's at
least three distinct, smaller effects, none of which has the bimodal legitimate/pathological gap
that made fix 4 possible.

**Mechanism A — `lopdf::Document::load`'s whole-file object-graph load, dominated by tagged-PDF
accessibility trees.** Instrumented `extract_text_from_mem` to return immediately after
`Document::load_mem` (before any content processing), isolating load-time RSS from
processing-time RSS. Two files in the survey are 88-92% load-driven:

| File | objects | `/StructElem` | load-only RSS | full RSS | load's share |
|---|---|---|---|---|---|
| `El_Salvador_PII/.../SampleFile_Passport_002.pdf` | 14,843 | 14,799 | 51MB | 55MB | 92% |
| `Colombia_PII/.../SampleFile_BankAccountNumber_001.pdf` | 21,604 | 20,134 | 75MB | 85MB | 88% |

Both are Word/Excel-style tagged-PDF exports with one `/StructElem` object per table cell
(`Table`/`TR`/`TD` structure, confirmed by grepping `/S` tag values). `lopdf::Document::load`
materializes the *entire* object graph unconditionally, before `pdf-extract` ever reaches a page.
This crate's `PlainTextOutput` never reads `StructTreeRoot`/`StructElem` — that memory buys
nothing for text extraction. Architecturally the same shape as fix 4 (an eager parser paying for
content we don't need) but one layer earlier, at document load rather than content-stream decode.

**Mechanism B — allocator high-water-mark retention across many small streams, not a leak.**
`Peru_PII/.../SampleFile_DriversLicense_001.pdf` has 1,032 distinct content streams, each
individually well under the fix-4 gate (aggregate 8.25MB across all of them). 28MB of its 52MB
peak RSS is load-time; the rest accumulates because each stream's `Vec<Operation>` is correctly
dropped after that stream, but macOS's allocator doesn't necessarily hand freed pages back to the
OS between drops — so peak *observed* RSS across hundreds of decode-then-drop cycles trends
upward even though nothing is actually retained live. Not fixable by gating content; would need
either a periodic OS-level "release free pages" call (`malloc_zone_pressure_relief` on macOS —
platform-specific, not currently used anywhere in this codebase) or acceptance.

**Mechanism C — the fix-4 byte threshold is a noisier cost proxy than the calibration assumed.**
`Nigeria_PII/.../SampleFile_TaxID_001.pdf`: only 37 objects, 15.9MB load-only RSS (cheap, as
expected) — but 78.5MB full RSS. One single content stream, 1.9MB (**under** the 2MB fix-4 gate,
correctly left alone), costs ~62MB to decode and process — a ~32x blow-up from decompressed-byte
count to processing cost. The 804KB-legitimate-case calibration implicitly assumed streams under
the gate cost a bounded, modest amount; this shows decompressed byte count doesn't tightly bound
processing cost on its own — operator density per byte varies more than the calibration data (a
200-file sample, mostly *not* pathological) surfaced.

**Followed the same discipline as fix 4 — surveyed before guessing at a threshold — and found no
usable one.** Extended the 200-file survey with the PDF trailer's `/Size` (total object count,
readable via a cheap regex scan, no full `lopdf` load needed) and `/StructElem` count:

- **Raw `/Size` has no clean gap.** Under-budget files: p50 84, p90 1,335, max 7,554. Over-budget
  files: min 37, p50 3,159, max 21,595. 153 of 182 under-budget files exceed the *smallest*
  over-budget file's object count, and the largest under-budget file (7,554 objects, 36MB) sits
  close to the smallest clearly object-count-driven pathological case (8,976 objects, 88MB, no
  struct tree at all — plain object count alone, independent of struct trees, still costs
  load-time RSS at a roughly similar ~3-5KB/object rate). The relationship looks close to
  **linear**, not bimodal: cost scales with object count rather than clustering into "normal" vs
  "extreme" groups the way content-stream bytes did.
- **`/StructElem` count alone looks more promising but is too thin to trust.** Legitimate
  struct-tree-bearing files topped out at 1,580 elements (23MB RSS); the smallest pathological
  struct-heavy case had 5,636 (97MB RSS) — a >3.5x gap. But only ~10 files in the 200-file sample
  carry a struct tree at all; this could be a real cliff or an artifact of which corpus files
  happen to exist at which sizes. Not enough data to calibrate a threshold with the same
  confidence as fix 4's 804KB/2.29MB split.

**Decision: no fifth fix.** A threshold/exclusion gate is the right tool for a bimodal
legitimate-vs-pathological split (fix 4's case). This residual is a continuous, roughly linear
resource-scaling characteristic instead — any single cutoff either lets real pathological cases
through or starts excluding ordinary complex documents (large but legitimate tagged-accessibility
exports are not rare or adversarial; Word/Excel routinely produce them). Actually fixing Mechanism
A would mean patching `lopdf`'s `Document`/`Dictionary` representation itself (skip or lazily load
objects unreachable from `/Pages`, e.g. `/StructTreeRoot`) — a foundational parser change, much
bigger and riskier than a targeted leaf-function patch like fixes 1-4, and out of scope here.

**Status: accepted, documented, open.** ~9% of a real-world corpus sample exceeds the strict 50MB
`CLAUDE.md` peak-RSS budget on complex/large PDFs (heavily-tagged accessibility exports, documents
with very many small objects, or dense-but-under-threshold vector content) — now understood, not
silently tolerated, but not further mitigated. If this becomes operationally significant, the
next real lever is either the `lopdf` representation patch above, or the higher-level control the
project has already flagged as missing for the embedded/FFI path: real per-file process isolation
(the production host currently has no equivalent of `--scan --isolate`'s per-file isolation).

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
- Fix 4's threshold came from a one-off survey script (`/usr/bin/time -l` over a sample of real
  PDFs, parsing peak RSS), not committed to this repo — external/proprietary corpus, ad-hoc
  analysis tooling. Re-derive it the same way if recalibrating: run it broadly (not just against
  known-bad files) so the threshold is set by the gap between legitimate and pathological, not by
  fitting to whatever triggered the investigation.
  `heaptrack`/`valgrind --tool=massif` aren't available on macOS at all — either would work on
  Linux if this needs revisiting with real tooling instead of hand-rolled allocators.

## If you're re-syncing with a newer upstream pdf-extract release

1. Check whether the new release has fixed fixes 1-3 itself (search `src/lib.rs` for the `"Do"`
   arm and the `"f*"`/`"s"`/`"B"`/`"B*"`/`"b"` dispatch in `process_stream`). As of 0.12.0 (checked
   2026-09), none were fixed — byte-for-byte identical to 0.9.0 in all three spots. Fix 4 (the
   size gate) is project-specific and has no upstream equivalent to check for.
2. Re-apply whichever of fixes 1-3 the new release hasn't already fixed itself (search
   `ENDPOINT-CI PATCH` comments in this version's `src/lib.rs` for the exact diffs), plus fix 4
   unconditionally, to the new version, update this directory's `Cargo.toml` version to match, and
   rebuild.
3. Re-run the size-gate survey (see "How this was found" above) against a real corpus rather than
   assuming the 2MB threshold still holds — a different pdf-extract/lopdf version could change how
   much a given amount of real content costs to represent as `Vec<Operation>`. On the original
   trigger file, the baseline with all four fixes applied is ~72MB peak RSS / ~0.74s, not near-zero
   — "still nonzero" doesn't mean your re-sync failed.
