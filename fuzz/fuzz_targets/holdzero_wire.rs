//! Fuzz `HybridMessage::from_wire` against arbitrary input.
//!
//! The wire parser is the first thing a stranger's first-contact bytes touch.
//! The property under test is totality: for ANY bytes it must return an `Option`
//! — never panic, index out of bounds, overflow, or abort.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = holdzero::HybridMessage::from_wire(data);
});
