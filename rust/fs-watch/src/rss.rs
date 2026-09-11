//! Peak resident set size and cumulative CPU time via `getrusage` -- duplicated from
//! `../../cli/src/rss.rs` rather than shared (it's ~50 lines and the two binaries otherwise have
//! no reason to depend on each other). Same sampling methodology as `--cpu-soak`, applied here to
//! a real filesystem-event stream instead of a synthetic one.

#[cfg(unix)]
fn getrusage_self() -> Option<libc::rusage> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    Some(unsafe { usage.assume_init() })
}

/// `None` on non-Unix.
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
/// `RUSAGE_SELF` sums across every thread; %CPU computed as cpu-time-delta / wall-time-delta can
/// exceed 100% during a multi-core burst, matching the `top`/`ps %CPU` convention.
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
