//! Fuzz `holdzero::open` against arbitrary input.
//!
//! `open` is the first thing a delivered packet touches on the recipient. The
//! property under test is totality: for ANY key and ANY bytes it must return an
//! `Option` — never panic, index out of bounds, overflow, or abort. A panic on a
//! malformed packet would be a remote denial of service.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&data[..32]);
        let _ = holdzero::open(&key, &data[32..]);
    }
});
