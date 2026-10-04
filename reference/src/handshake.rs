//! MIDDLE SLOT — the silent handshake.
//!
//! Before any content is sent, each side proves it holds the shared hybrid key
//! by sending a short MAC over the handshake transcript — never the key itself.
//! The other side recomputes the MAC and compares in constant time. A non-holder
//! cannot produce the proof, so verification fails and nothing proceeds: no
//! content ever exists for them to attack.
//!
//! `BLAKE2b` is used as a prefix-MAC (secure for `BLAKE2` by design):
//! `tag = H(label || key || role || transcript)`, truncated to 32 bytes.

use blake2::{Blake2b512, Digest};
use subtle::ConstantTimeEq;

use crate::HYBRID_KEY_LEN;

const HS_LABEL: &[u8] = b"dd-silent-handshake-v1";

/// Proof length in bytes.
pub const TAG_LEN: usize = 32;

/// Role marker for the side that initiated contact.
pub const ROLE_SENDER: u8 = 1;
/// Role marker for the side that accepted contact.
pub const ROLE_RECIPIENT: u8 = 2;

/// Compute this side's proof of key possession over the transcript.
#[must_use]
pub fn proof(key: &[u8; HYBRID_KEY_LEN], role: u8, transcript: &[u8]) -> [u8; TAG_LEN] {
    let mut h = Blake2b512::new();
    h.update(HS_LABEL);
    h.update(key);
    h.update([role]);
    h.update(transcript);
    let full = h.finalize();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full[..TAG_LEN]);
    tag
}

/// Constant-time check of a proof presented by the other side.
#[must_use]
pub fn verify(
    key: &[u8; HYBRID_KEY_LEN],
    role: u8,
    transcript: &[u8],
    presented: &[u8; TAG_LEN],
) -> bool {
    proof(key, role, transcript).ct_eq(presented).into()
}
