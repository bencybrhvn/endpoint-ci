//! Peak resident set size and cumulative CPU time via `getrusage` — the same OS API Go's
//! `maxRSSBytes()` (in `../../cmd/ch-inspect/main.go`) calls via `syscall.Getrusage`.
//! `max_rss_bytes` is shared by `--bench` and `--scan`, both of which check the ≤50MB budget
//! line in `../../CLAUDE.md`. `cpu_time` is used by `--cpu-soak`, which checks the separate
//! ≤3% *sustained* CPU budget line -- a different question `--bench`/`--scan` don't answer,
//! since a low per-call latency can still add up to meaningful CPU% if events arrive often
//! enough over time.

#[cfg(unix)]
fn getrusage_self() -> Option<libc::rusage> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    Some(unsafe { usage.assume_init() })
}

/// `None` on non-Unix (mirrors Go's own Linux/macOS-only coverage there).
#[cfg(unix)]
pub fn max_rss_bytes() -> Option<u64> {
    let usage = getrusage_self()?;
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

/// Cumulative user+system CPU time consumed by this process (all threads) since it started.
/// `RUSAGE_SELF` sums across every thread, which is what we want for a process-level CPU%:
/// a burst that fans out across N cores for a moment still costs real CPU, and %CPU computed
/// this way (cpu-time-delta / wall-time-delta) can exceed 100% during such a burst, matching
/// the convention `top`/`ps %CPU` use -- not a bug, just what "3% of a core" budget language
/// implicitly assumes as its unit.
#[cfg(unix)]
pub fn cpu_time() -> Option<std::time::Duration> {
    let usage = getrusage_self()?;
    let to_dur = |tv: libc::timeval| std::time::Duration::new(tv.tv_sec as u64, (tv.tv_usec as u32) * 1000);
    Some(to_dur(usage.ru_utime) + to_dur(usage.ru_stime))
}

#[cfg(not(unix))]
pub fn cpu_time() -> Option<std::time::Duration> {
    None
}
