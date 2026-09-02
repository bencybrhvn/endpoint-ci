//! C ABI surface for `ch-inspect-core`, callable from C#, Swift, or C/C++ hosts (Windows/macOS/
//! Linux endpoint sensors respectively). See `include/ch_inspect.h` for the matching C header.
//!
//! Every exported fn wraps its body in `catch_unwind`: an unwind that crosses an `extern "C"`
//! boundary into a non-Rust host is process corruption, not a recoverable error (same pattern as
//! `dataflow/Sensors/AI/cyberhaven-agent-inspector/ca`). Build with:
//!   cargo build -p ch-inspect-ffi --profile release-ffi
//! (`panic = "unwind"`, not the workspace-default `"abort"` — see `../Cargo.toml`.)
//!
//! Reports cross the boundary as a JSON string (`engine::Report`'s existing `serde` shape) rather
//! than a hand-mirrored C struct — the report has ~10 fields including nested vecs, and every
//! host here already needs a JSON parser for other purposes, so this keeps the C surface small
//! and stable as the report shape evolves. Handles (`ChInspectDb`) are always opaque pointers.

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char};
use std::panic::AssertUnwindSafe;
use std::ptr;

use ch_inspect_core::{engine, extract, rules};

/// Opaque handle to a loaded rule database. Read-only after `ch_inspect_db_load` returns (see
/// `../../CLAUDE.md`'s thread-safety note), so the same handle may be used concurrently from
/// multiple host threads; never mutate or free it from more than one place.
pub struct ChInspectDb(rules::DB);

thread_local! {
    /// Message from the most recent failing call on this thread, for `ch_inspect_last_error`.
    /// Thread-local (not a shared global) so concurrent callers on different threads never race
    /// on each other's errors.
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn set_last_error(msg: impl Into<Vec<u8>>) {
    let cstr = CString::new(msg).unwrap_or_else(|_| c"error message contained an embedded NUL".to_owned());
    LAST_ERROR.with(|cell| *cell.borrow_mut() = Some(cstr));
}

/// Returns the message set by the most recent failing call *on the calling thread*, or null if
/// none has failed yet. The returned pointer is owned by this library — valid only until the next
/// `ch_inspect_*` call on the same thread, and must NOT be freed by the caller.
#[unsafe(no_mangle)]
pub extern "C" fn ch_inspect_last_error() -> *const c_char {
    LAST_ERROR.with(|cell| cell.borrow().as_ref().map_or(ptr::null(), |c| c.as_ptr()))
}

/// Reads a NUL-terminated UTF-8 C string. Caller retains ownership; the returned `&str` borrows
/// from it and must not outlive it.
unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Err("null string argument".to_string());
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|e| format!("string argument is not valid UTF-8: {e}"))
}

unsafe fn db_ref<'a>(db: *const ChInspectDb) -> Result<&'a rules::DB, String> {
    if db.is_null() {
        return Err("null db handle".to_string());
    }
    Ok(&unsafe { &*db }.0)
}

/// Serialises a report to a heap C string the caller owns, or null (with `ch_inspect_last_error`
/// set) if serialisation somehow fails (report field types make this unreachable in practice —
/// `serde_json` cannot fail on `Report`'s all-owned, non-map-with-non-string-key shape — but a
/// panic-safe FFI boundary reports the failure rather than unwrapping).
fn report_to_cstring(report: &engine::Report) -> *mut c_char {
    let json = match serde_json::to_string(report) {
        Ok(j) => j,
        Err(e) => {
            set_last_error(format!("serialising report: {e}"));
            return ptr::null_mut();
        }
    };
    match CString::new(json) {
        Ok(c) => c.into_raw(),
        Err(e) => {
            set_last_error(format!("report JSON contained an embedded NUL: {e}"));
            ptr::null_mut()
        }
    }
}

/// Loads a rule database from a `rules.json` path (lexicon paths inside it resolve relative to
/// the rules file, not the process's current directory — see `rules::load`). Returns an opaque
/// handle to free later with `ch_inspect_db_free`, or null on failure (`ch_inspect_last_error`
/// has the reason: bad path, unreadable file, malformed JSON, or a pattern that isn't RE2-valid).
///
/// # Safety
/// `rules_path` must be null or a valid pointer to a NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ch_inspect_db_load(rules_path: *const c_char) -> *mut ChInspectDb {
    std::panic::catch_unwind(AssertUnwindSafe(|| db_load(rules_path))).unwrap_or_else(|_| {
        set_last_error("panic while loading rules");
        ptr::null_mut()
    })
}

fn db_load(rules_path: *const c_char) -> *mut ChInspectDb {
    let path = match unsafe { cstr_to_str(rules_path) } {
        Ok(p) => p,
        Err(e) => {
            set_last_error(e);
            return ptr::null_mut();
        }
    };
    match rules::load(path) {
        Ok(db) => Box::into_raw(Box::new(ChInspectDb(db))),
        Err(e) => {
            set_last_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Frees a handle returned by `ch_inspect_db_load`. Null is a no-op. The handle must not be used
/// (by any thread) after this call, and must not be freed twice.
///
/// # Safety
/// `db` must be null or a pointer previously returned by `ch_inspect_db_load` and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ch_inspect_db_free(db: *mut ChInspectDb) {
    if db.is_null() {
        return;
    }
    let _ = std::panic::catch_unwind(AssertUnwindSafe(|| unsafe { drop(Box::from_raw(db)) }));
}

/// Inspects the file at `path` (read from disk) and returns its match report as a heap-owned,
/// NUL-terminated JSON C string — free it with `ch_inspect_free_string`. Returns null on failure
/// (bad handle, bad path, or unreadable file — see `ch_inspect_last_error`); an unreadable
/// *content* (encrypted/corrupt/binary) is not a failure, it's a report with `readable: false`.
///
/// # Safety
/// `db` must be a live pointer from `ch_inspect_db_load`. `path` must be null or a valid pointer
/// to a NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ch_inspect_file(db: *const ChInspectDb, path: *const c_char) -> *mut c_char {
    std::panic::catch_unwind(AssertUnwindSafe(|| inspect_file(db, path))).unwrap_or_else(|_| {
        set_last_error("panic while inspecting file");
        ptr::null_mut()
    })
}

fn inspect_file(db: *const ChInspectDb, path: *const c_char) -> *mut c_char {
    let db = match unsafe { db_ref(db) } {
        Ok(d) => d,
        Err(e) => {
            set_last_error(e);
            return ptr::null_mut();
        }
    };
    let path = match unsafe { cstr_to_str(path) } {
        Ok(p) => p,
        Err(e) => {
            set_last_error(e);
            return ptr::null_mut();
        }
    };
    match engine::inspect_file(path, db, extract::Config::default()) {
        Ok(report) => report_to_cstring(&report),
        Err(e) => {
            set_last_error(format!("reading {path}: {e}"));
            ptr::null_mut()
        }
    }
}

/// Inspects an in-memory buffer (no filesystem access) and returns its match report as a
/// heap-owned, NUL-terminated JSON C string — free it with `ch_inspect_free_string`. `name` is a
/// label for the report only (e.g. an original filename); it need not exist on disk. Returns null
/// only on a bad handle/argument (see `ch_inspect_last_error`) — an unreadable buffer content
/// still produces a report, not a failure.
///
/// # Safety
/// `data` must point to at least `data_len` readable bytes, or be null with `data_len == 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ch_inspect_data(db: *const ChInspectDb, name: *const c_char, data: *const u8, data_len: usize) -> *mut c_char {
    std::panic::catch_unwind(AssertUnwindSafe(|| unsafe { inspect_data(db, name, data, data_len) })).unwrap_or_else(|_| {
        set_last_error("panic while inspecting data");
        ptr::null_mut()
    })
}

unsafe fn inspect_data(db: *const ChInspectDb, name: *const c_char, data: *const u8, data_len: usize) -> *mut c_char {
    let db = match unsafe { db_ref(db) } {
        Ok(d) => d,
        Err(e) => {
            set_last_error(e);
            return ptr::null_mut();
        }
    };
    let name = match unsafe { cstr_to_str(name) } {
        Ok(n) => n,
        Err(e) => {
            set_last_error(e);
            return ptr::null_mut();
        }
    };
    if data.is_null() && data_len != 0 {
        set_last_error("null data pointer with non-zero data_len");
        return ptr::null_mut();
    }
    let bytes: &[u8] = if data_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(data, data_len) }
    };
    let report = engine::inspect_data(name, bytes, db, extract::Config::default());
    report_to_cstring(&report)
}

/// Frees a JSON string returned by `ch_inspect_file` or `ch_inspect_data`. Null is a no-op. Must
/// not be called on any other pointer, and not called twice on the same one.
///
/// # Safety
/// `s` must be null or a pointer previously returned by `ch_inspect_file`/`ch_inspect_data` and
/// not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ch_inspect_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    let _ = std::panic::catch_unwind(AssertUnwindSafe(|| unsafe { drop(CString::from_raw(s)) }));
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::path::PathBuf;

    use super::*;

    fn repo_root() -> PathBuf {
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
    }

    fn load_real_db() -> *mut ChInspectDb {
        let path = repo_root().join("config/rules.json");
        let path = CString::new(path.to_str().unwrap()).unwrap();
        let db = unsafe { ch_inspect_db_load(path.as_ptr()) };
        assert!(!db.is_null(), "load failed: {:?}", last_error());
        db
    }

    fn last_error() -> Option<String> {
        let p = ch_inspect_last_error();
        if p.is_null() {
            return None;
        }
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }

    fn take_json(json_ptr: *mut c_char) -> engine::Report {
        assert!(!json_ptr.is_null(), "expected a report, got null: {:?}", last_error());
        let json = unsafe { CStr::from_ptr(json_ptr) }.to_str().unwrap().to_owned();
        let report = serde_json::from_str(&json).expect("valid report JSON");
        unsafe { ch_inspect_free_string(json_ptr) };
        report
    }

    #[test]
    fn round_trips_a_real_rules_file() {
        let db = load_real_db();
        unsafe { ch_inspect_db_free(db) };
    }

    #[test]
    fn load_reports_a_useful_error_on_a_bad_path() {
        let bad = CString::new("/no/such/rules.json").unwrap();
        let db = unsafe { ch_inspect_db_load(bad.as_ptr()) };
        assert!(db.is_null());
        // rules::load's io::Error::to_string() doesn't echo the path back (e.g. just "No such
        // file or directory (os error 2)"), so only assert that some reason was set.
        assert!(!last_error().unwrap().is_empty());
    }

    #[test]
    fn load_null_path_is_a_clean_failure_not_a_crash() {
        let db = unsafe { ch_inspect_db_load(ptr::null()) };
        assert!(db.is_null());
        assert_eq!(last_error().unwrap(), "null string argument");
    }

    #[test]
    fn inspect_data_round_trips_and_matches_a_known_profile() {
        let db = load_real_db();
        let name = CString::new("dense.txt").unwrap();
        let text = "Card 4111111111111111 SSN 123-45-6789 email john.doe@example.com";
        let json_ptr = unsafe { ch_inspect_data(db, name.as_ptr(), text.as_ptr(), text.len()) };
        let report = take_json(json_ptr);
        assert!(report.matched(), "expected at least one profile to match: {report:?}");
        unsafe { ch_inspect_db_free(db) };
    }

    #[test]
    fn inspect_file_round_trips_a_real_fixture() {
        let db = load_real_db();
        let path = repo_root().join("testdata/corpus/pci_card.txt");
        let path = CString::new(path.to_str().unwrap()).unwrap();
        let json_ptr = unsafe { ch_inspect_file(db, path.as_ptr()) };
        let report = take_json(json_ptr);
        assert!(report.matched(), "expected at least one profile to match: {report:?}");
        unsafe { ch_inspect_db_free(db) };
    }

    #[test]
    fn inspect_file_missing_path_is_a_clean_failure_not_a_crash() {
        let db = load_real_db();
        let path = CString::new("/no/such/file.txt").unwrap();
        let json_ptr = unsafe { ch_inspect_file(db, path.as_ptr()) };
        assert!(json_ptr.is_null());
        assert!(last_error().is_some());
        unsafe { ch_inspect_db_free(db) };
    }

    #[test]
    fn inspect_data_null_db_is_a_clean_failure_not_a_crash() {
        let name = CString::new("x.txt").unwrap();
        let json_ptr = unsafe { ch_inspect_data(ptr::null(), name.as_ptr(), ptr::null(), 0) };
        assert!(json_ptr.is_null());
        assert_eq!(last_error().unwrap(), "null db handle");
    }

    #[test]
    fn inspect_data_empty_buffer_is_a_report_not_a_failure() {
        let db = load_real_db();
        let name = CString::new("empty.txt").unwrap();
        let json_ptr = unsafe { ch_inspect_data(db, name.as_ptr(), ptr::null(), 0) };
        let report = take_json(json_ptr);
        assert!(!report.matched());
        unsafe { ch_inspect_db_free(db) };
    }

    #[test]
    fn frees_and_nulls_are_no_ops() {
        unsafe {
            ch_inspect_db_free(ptr::null_mut());
            ch_inspect_free_string(ptr::null_mut());
        }
    }
}
