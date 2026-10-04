//! OUTER SLOT — the deception layer.
//!
//! A real sealed packet is already a fixed size (`PACKET_LEN`) and looks random.
//! This slot produces cover decoys: packets of the exact same size and random
//! appearance, so an observer without the key cannot tell a real message from
//! noise — or whether a message was sent at all.
//!
//! Cover bytes are expanded deterministically from a seed (`BLAKE2b` in counter
//! mode) so tests are reproducible; in production the seed is random. This never
//! touches anyone else's machine — it only shapes what we emit.

use blake2::{Blake2b512, Digest};

use crate::PACKET_LEN;

const FILLER_LABEL: &[u8] = b"dd-cover-v1";

/// Expand `seed` into `out` bytes using `BLAKE2b` in counter mode.
fn expand(seed: &[u8], out: &mut [u8]) {
    let mut counter: u64 = 0;
    let mut off = 0;
    while off < out.len() {
        let mut h = Blake2b512::new();
        h.update(FILLER_LABEL);
        h.update(seed);
        h.update(counter.to_le_bytes());
        let block = h.finalize();
        let n = core::cmp::min(block.len(), out.len() - off);
        out[off..off + n].copy_from_slice(&block[..n]);
        off += n;
        counter += 1;
    }
}

/// A cover (decoy) packet: exactly `PACKET_LEN` random-looking bytes, the same
/// size and shape as a real sealed packet. It carries no message and never opens.
#[must_use]
pub fn cover_packet(seed: &[u8; 32]) -> Vec<u8> {
    let mut out = vec![0u8; PACKET_LEN];
    expand(seed, &mut out);
    out
}

/// True if a packet is the size an on-wire packet must be. An observer can check
/// this; it tells them nothing about whether the packet is real or cover.
#[must_use]
pub fn is_well_formed(packet: &[u8]) -> bool {
    packet.len() == PACKET_LEN
}
