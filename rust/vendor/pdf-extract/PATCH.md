# Why this crate is vendored, and what's patched (and what's NOT fully fixed yet)

`pdf-extract` 0.9.0 from crates.io, vendored here with two patches applied. Wired in via
`../../Cargo.toml`'s `[patch.crates-io]` section, which replaces every use of the registry
`pdf-extract` crate across the whole workspace with this copy — no call-site changes needed
anywhere else in the codebase.

**Read this whole file before assuming the RSS spike below is closed. It isn't, fully.**

## The bug that started this

Found 2026-09 via `--cpu-soak` (see `rust/cli/src/soak.rs`), which runs the engine warm and
in-process — the shape a real embedding (`ch-inspect-ffi`) has, unlike `--scan --isolate`'s
fresh-process-per-file dev tooling. A legitimate, non-malicious 5.8MB real-world PDF
(`Bank_Account_Number/Matches/SampleFile_Ecuador_BAN_001.pdf` in the Nucleuz corpus — external,
not vendored in this repo) drove peak RSS to **587MB** and cost 1.34s CPU to extract.

This is a *different* problem from the already-known/mitigated "malformed PDF OOMs to
multi-GB" bomb-file class documented in `../../../DECISIONS.md` (mitigated by `--scan --isolate`'s
per-file process isolation — a bomb only kills its own child). The file here is well-formed;
`pdfinfo`/`pdfimages -list` show a normal 10-page LibreOffice-produced PDF with 607 distinct
Form/Image XObjects and ~35-60MB of embedded image data (mostly reused across pages 5-6). The real
production embedding path has no equivalent of `--scan --isolate`'s isolation — it runs in-process,
warm, inside whatever host embeds it — so a wrapper-level size cap (bounding the blast radius, not
fixing the defect) felt like settling for less than we should.

## Two real, verified defects fixed here

**1. `Do` never checked `/Subtype` before recursing (fixed, verified).** `process_stream`'s `"Do"`
operator handler recursively parses the referenced XObject's content as PDF drawing commands
unconditionally. `Do` is used for both `/Form` XObjects (genuine nested content streams) and
`/Image` XObjects (raw, often JPEG-compressed bitmap bytes) — the unpatched code fed *both*
through the content-stream tokenizer as if they were syntax. Confirmed via instrumentation: 37 of
this file's 619 `Do` invocations were images being mis-parsed as commands. Fix: check `/Subtype`
via `maybe_get_name_string` (previously dead code) and skip recursion for `/Image`. Spec-correct,
not a heuristic — only `/Form` XObjects can contain nested content per the PDF spec, so no
legitimate content is ever skipped.

**2. No memoization of repeated Forms or fonts across a document (fixed, verified).** The original
code re-extracts a Form XObject's content and re-runs `make_font` on a font's descriptor/widths
every single time either is referenced, even when the *same* object is referenced many times
across a document (e.g. a repeated logo, or a handful of real fonts used by hundreds of small
Forms — this file has 607 distinct Form/Image objects). Added a `Processor`-level
`visited_xobjects: HashSet<ObjectId>` (skip a Form/Image already extracted once, document-wide)
and `font_cache: HashMap<ObjectId, Rc<dyn PdfFont>>` (build a font's table once, keyed by its
object reference rather than the per-stream local resource name). Both are spec-correct: a Form's
content and a font's metrics are fixed regardless of how many times or where they're
referenced, so caching never loses distinct output, only eliminates redundant re-work.

## What these two fixes did NOT do: fully close the 587MB spike

Both fixes are real, instrumentation-verified, and directionally correct. **Neither individually
nor together did they bring this specific file's peak RSS down from ~587MB in testing** (still
measured ~586-600MB after both patches). Root-caused as far as time allowed:

- Confirmed via a depth counter: recursion is only 1 level deep (607 *siblings*, not a deep
  chain) — ruled out unbounded recursion depth as the cause.
- Confirmed via a direct length check: the final extracted text is genuinely only ~9KB — ruled out
  a runaway output-string buffer.
- A custom-allocator diagnostic (tracking allocation size/count) showed many small (480/960-byte)
  allocations accumulating as *live* (not-yet-freed) memory over the run, consistent with some
  per-object working state (plausibly path-drawing data, `Vec<PathOp>`, given `PathOp`'s ~48-56
  byte size is in the right range) that isn't being released between the 607 sequential Form/Image
  calls — but a `Mutex`-based version of that same diagnostic **segfaulted the process** (a global
  allocator taking a lock is inherently reentrancy-risky), so this was not conclusively pinned down
  before the investigation had to stop. `dtrace`-based allocation profiling would likely have
  settled it, but requires `sudo`, which wasn't available in this session.
- A proper in-process memory *ceiling* (a capacity-limited global allocator that aborts cleanly
  once a cap is hit) is not safely achievable on stable Rust: `GlobalAlloc::alloc` must not panic
  or unwind (that's UB), and returning null triggers `alloc_error_handler`, which is
  nightly-only and defaults to aborting the whole process anyway if not overridden — i.e. the same
  failure mode we're trying to avoid, just faster.

**If you pick this back up:** get `dtrace` allocation-profiling access (needs `sudo`) or build on
Linux where `heaptrack`/`valgrind --tool=massif` are available, and get a real symbolized
allocation-site report rather than continuing to guess-and-instrument. Until then, treat the ~35-
60MB of embedded image data plus 607 distinct Form objects as the likely remaining suspects, in
that rough order.

## If you're re-syncing with a newer upstream pdf-extract release

1. Check whether the new release has fixed the `/Subtype` issue itself (search `src/lib.rs` for
   the `"Do"` arm in `process_stream`). As of 0.12.0 (checked 2026-09), it hadn't — byte-for-byte
   identical to 0.9.0's handler.
2. If not, re-apply both patches (search `ENDPOINT-CI PATCH` comments in this version's
   `src/lib.rs` for the exact diffs) to the new version, update this directory's `Cargo.toml`
   version to match, and rebuild.
3. Re-run `--cpu-soak` (or at minimum `/usr/bin/time -l ... --file <the file above>`, if you have
   access to the external Nucleuz corpus) — remember the baseline is ~587MB even with both patches
   applied, so "still high" doesn't mean your re-sync failed.
