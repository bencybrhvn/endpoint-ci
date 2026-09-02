/* C ABI for ch-inspect-core, the local content-inspection engine (see ../src/lib.rs).
 *
 * Hand-maintained to match the `#[unsafe(no_mangle)] pub unsafe extern "C" fn` exports in
 * ../src/lib.rs -- if you add, remove, or change a signature there, update this header in the
 * same change.
 *
 * Build ch-inspect-ffi with:
 *   cargo build -p ch-inspect-ffi --profile release-ffi
 * which produces a cdylib named `ch_inspect` (libch_inspect.{dylib,so} / ch_inspect.dll).
 *
 * Thread safety: a `ch_inspect_db*` handle is read-only after `ch_inspect_db_load` returns, so
 * the same handle may be inspected from multiple threads concurrently. `ch_inspect_last_error`
 * is thread-local -- it reports the last failure *on the calling thread*, not globally.
 *
 * Ownership: every non-null pointer this library hands back (a db handle, a report string) is
 * owned by the library until you pass it to the matching `_free` function exactly once. Never
 * free a pointer this library did not return, and never use a handle/string after freeing it.
 */
#ifndef CH_INSPECT_H
#define CH_INSPECT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle to a loaded rule database. */
typedef struct ch_inspect_db ch_inspect_db;

/*
 * Returns the message set by the most recent failing call on the calling thread, or NULL if
 * none has failed yet. The returned pointer is owned by the library -- valid only until the
 * next ch_inspect_* call on this thread. Do not free it.
 */
const char *ch_inspect_last_error(void);

/*
 * Loads a rule database from a rules.json path (UTF-8, NUL-terminated). Lexicon paths inside
 * rules.json resolve relative to the rules file, not the process's current directory.
 *
 * Returns an opaque handle to release later with ch_inspect_db_free, or NULL on failure (call
 * ch_inspect_last_error() for the reason: bad path, unreadable file, malformed JSON, or a
 * pattern that isn't RE2-valid).
 */
ch_inspect_db *ch_inspect_db_load(const char *rules_path);

/*
 * Releases a handle returned by ch_inspect_db_load. NULL is a no-op. The handle must not be
 * used by any thread after this call, and must not be freed twice.
 */
void ch_inspect_db_free(ch_inspect_db *db);

/*
 * Inspects the file at `path` (read from disk) and returns its match report as a heap-owned,
 * NUL-terminated JSON string -- release it with ch_inspect_free_string. The JSON shape is
 * ch-inspect-core's engine::Report (profiles/detectors/labels + neutral scan facts; this
 * engine reports matches, it never decides an action).
 *
 * Returns NULL on failure (bad handle, bad path, or unreadable file -- see
 * ch_inspect_last_error()). An unreadable *content* (encrypted/corrupt/binary) is not a
 * failure -- it comes back as a report with "readable": false.
 */
char *ch_inspect_file(const ch_inspect_db *db, const char *path);

/*
 * Inspects an in-memory buffer (no filesystem access) and returns its match report as a
 * heap-owned, NUL-terminated JSON string -- release it with ch_inspect_free_string. `name` is
 * a label for the report only (e.g. an original filename); it need not exist on disk. `data`
 * must point to at least `data_len` readable bytes, or be NULL with `data_len` == 0.
 *
 * Returns NULL only on a bad handle/argument (see ch_inspect_last_error()) -- an unreadable
 * buffer content still produces a report, not a failure.
 */
char *ch_inspect_data(const ch_inspect_db *db, const char *name, const unsigned char *data, size_t data_len);

/*
 * Releases a JSON string returned by ch_inspect_file or ch_inspect_data. NULL is a no-op. Must
 * not be called on any other pointer, and not called twice on the same one.
 */
void ch_inspect_free_string(char *s);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CH_INSPECT_H */
