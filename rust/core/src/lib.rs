//! Core content-inspection engine — Rust port of the Go reference implementation.
//!
//! Ported module-by-module against `../../internal/*`; the Go tree stays untouched as the
//! parity oracle (see ../../DECISIONS.md). Nothing here talks to the OS or decides an FFI
//! boundary — that's `ch-inspect-ffi`'s job. Nothing here decides policy — this engine reports
//! matches, it never blocks (see ../../DECISIONS.md, 2026-07-07).

pub mod engine;
pub mod extract;
pub mod format;
pub mod label;
pub mod prefilter;
pub mod profile;
pub mod rules;
pub mod scan;
#[cfg(test)]
mod testutil;
mod util;
pub mod validators;
