//! Peak resident set size via `getrusage` — the same OS API Go's `maxRSSBytes()` (in
//! `../../cmd/ch-inspect/main.go`) calls via `syscall.Getrusage`. Shared by `--bench` and
//! `--scan`, both of which check the ≤50MB budget line in `../../CLAUDE.md`.

/// `None` on non-Unix (mirrors Go's own Linux/macOS-only coverage there).
#[cfg(unix)]
pub fn max_rss_bytes() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    let usage = unsafe { usage.assume_init() };
    // Linux reports KB, macOS/BSD report bytes.
    #[cfg(target_os = "linux")]
    let bytes = usage.ru_maxrss as u64 * 1024;
    #[cfg(not(target_os = "linux"))]
    let bytes = usage.ru_maxrss as u64;
    Some(bytes)
}

#[cfg(not(unix))]
pub fn max_rss_bytes() -> Option<u64> {
    None
}
