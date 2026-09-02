//! C ABI surface for `ch-inspect-core`, callable from C#, Swift, or C/C++ hosts.
//!
//! Placeholder — no exported functions yet. When the first entry point lands, follow the
//! pattern in `dataflow/Sensors/AI/cyberhaven-agent-inspector/ca`: every `extern "C"` fn wraps
//! its body in `std::panic::catch_unwind` (an unwind crossing the FFI boundary is host-process
//! corruption, not a recoverable error) and returns a plain status code / out-pointer rather
//! than anything Rust-specific.
