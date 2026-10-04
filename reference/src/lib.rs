//! HZ-25519-761 ("`HoldZero`") — the three-slot protocol, reference build.
//!
//! A message is built as nested envelopes with named, swappable slots:
//!
//! - INNER (this file): the locks. `X25519` + `sntrup761` hybrid key agreement,
//!   then a fixed-size content seal under that key. Built so a third
//!   experimental lock can be folded into `combine` later without disturbing the
//!   two proven ones.
//! - MIDDLE (`handshake`): the message rules. A silent handshake — both sides
//!   prove they hold the shared key before any content exists; a non-holder gets
//!   silence.
//! - OUTER (`deception`): cover traffic. A real sealed packet is a fixed size and
//!   looks random, so a decoy is indistinguishable from a real one.
//!
//! `protocol` wires the three together into one first-contact-then-send flow.
//!
//! Reference/experimental only (`publish = false`): proven here against the
//! primitives' own reference vectors. Nothing here is a user's only lock — the
//! post-quantum and classical locks always ride together — and it is not on the
//! app build path.

use blake2::{Blake2b512, Digest};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use sntrup761::{Ciphertext, DecapsulationKey, EncapsulationKey, CIPHERTEXT_SIZE};
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};

pub mod deception;
pub mod handshake;
pub mod protocol;

/// Length of the derived hybrid key in bytes.
pub const HYBRID_KEY_LEN: usize = 32;

/// Domain-separation label: ties a derived key to this exact construction.
const LABEL: &[u8] = b"dd-hybrid-x25519-sntrup761-v1";

/// What the sender transmits so the recipient can derive the same key.
pub struct HybridMessage {
    /// The sender's ephemeral `X25519` public key.
    pub x_ephemeral_public: [u8; 32],
    /// The `sntrup761` ciphertext encapsulating the post-quantum shared secret.
    pub pq_ciphertext: Ciphertext,
}

impl HybridMessage {
    /// The transcript bytes the handshake proofs are bound to: everything the
    /// sender put on the wire for this exchange.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        let mut t = Vec::with_capacity(32 + CIPHERTEXT_SIZE);
        t.extend_from_slice(&self.x_ephemeral_public);
        t.extend_from_slice(self.pq_ciphertext.as_ref());
        t
    }

    /// Parse a `HybridMessage` from its on-wire bytes: `x_ephemeral_public(32)`
    /// followed by the `sntrup761` ciphertext. Returns `None` on any wrong size
    /// or malformed ciphertext — never panics, so it is safe on hostile input.
    #[must_use]
    pub fn from_wire(bytes: &[u8]) -> Option<HybridMessage> {
        if bytes.len() != 32 + CIPHERTEXT_SIZE {
            return None;
        }
        let mut x_ephemeral_public = [0u8; 32];
        x_ephemeral_public.copy_from_slice(&bytes[..32]);
        let pq_ciphertext = Ciphertext::try_from(&bytes[32..]).ok()?;
        Some(HybridMessage {
            x_ephemeral_public,
            pq_ciphertext,
        })
    }
}

/// Fold both shared secrets and the full transcript into one 32-byte key.
///
/// Extension point (third lock): to add an experimental outer lock later, fold
/// its shared secret in here as one more `update` before `finalize`. The two
/// proven halves still gate the key, so a broken experiment cannot weaken it.
fn combine(
    x_shared: &[u8; 32],
    pq_shared: &[u8],
    x_ephemeral_public: &[u8; 32],
    x_recipient_public: &[u8; 32],
    pq_ciphertext: &[u8],
) -> [u8; HYBRID_KEY_LEN] {
    let mut h = Blake2b512::new();
    h.update(LABEL);
    h.update(x_shared);
    h.update(pq_shared);
    h.update(x_ephemeral_public);
    h.update(x_recipient_public);
    h.update(pq_ciphertext);
    let full = h.finalize();
    let mut key = [0u8; HYBRID_KEY_LEN];
    key.copy_from_slice(&full[..HYBRID_KEY_LEN]);
    key
}

/// Sender side of the hybrid key agreement. The seeds make it reproducible for
/// tests; in production they are random.
#[must_use]
pub fn sender_initiate(
    x_recipient_public: &[u8; 32],
    pq_recipient_public: &EncapsulationKey,
    x_ephemeral_secret: [u8; 32],
    pq_seed: [u8; 32],
) -> (HybridMessage, [u8; HYBRID_KEY_LEN]) {
    let x_eph = XSecret::from(x_ephemeral_secret);
    let x_eph_pub = XPublic::from(&x_eph);
    let x_recip_pub = XPublic::from(*x_recipient_public);
    let x_shared = x_eph.diffie_hellman(&x_recip_pub);

    let (pq_ct, pq_shared) = pq_recipient_public.encapsulate_deterministic(pq_seed);

    let key = combine(
        x_shared.as_bytes(),
        pq_shared.as_ref(),
        x_eph_pub.as_bytes(),
        x_recipient_public,
        pq_ct.as_ref(),
    );
    (
        HybridMessage {
            x_ephemeral_public: *x_eph_pub.as_bytes(),
            pq_ciphertext: pq_ct,
        },
        key,
    )
}

/// Recipient side: recover the same key from the message and both static secrets.
#[must_use]
pub fn recipient_accept(
    x_recipient_secret: &[u8; 32],
    pq_recipient_secret: &DecapsulationKey,
    msg: &HybridMessage,
) -> [u8; HYBRID_KEY_LEN] {
    let x_recip = XSecret::from(*x_recipient_secret);
    let x_recip_pub = XPublic::from(&x_recip);
    let x_eph_pub = XPublic::from(msg.x_ephemeral_public);
    let x_shared = x_recip.diffie_hellman(&x_eph_pub);

    let pq_shared = pq_recipient_secret.decapsulate(&msg.pq_ciphertext);

    combine(
        x_shared.as_bytes(),
        pq_shared.as_ref(),
        &msg.x_ephemeral_public,
        x_recip_pub.as_bytes(),
        msg.pq_ciphertext.as_ref(),
    )
}

/// `XChaCha20-Poly1305` nonce length.
pub const NONCE_LEN: usize = 24;
/// Fixed padded-plaintext size (2-byte length header + up to `MAX_MESSAGE_LEN`).
pub const BODY_LEN: usize = 256;
/// Every sealed packet is exactly this many bytes.
pub const PACKET_LEN: usize = NONCE_LEN + BODY_LEN + 16;
/// Largest message that fits one packet.
pub const MAX_MESSAGE_LEN: usize = BODY_LEN - 2;

/// Seal a message under the hybrid key into a fixed-size `PACKET_LEN` packet.
///
/// The plaintext is padded to a fixed size before sealing, so the true message
/// length never leaks. Returns `None` if the message is longer than
/// `MAX_MESSAGE_LEN`. The `nonce` is caller-supplied (random in production).
#[must_use]
pub fn seal(
    key: &[u8; HYBRID_KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    message: &[u8],
) -> Option<Vec<u8>> {
    let len = u16::try_from(message.len()).ok()?;
    if message.len() > MAX_MESSAGE_LEN {
        return None;
    }
    let mut body = [0u8; BODY_LEN];
    body[..2].copy_from_slice(&len.to_be_bytes());
    body[2..2 + message.len()].copy_from_slice(message);

    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let ct = cipher
        .encrypt(XNonce::from_slice(nonce), body.as_ref())
        .ok()?;

    let mut packet = Vec::with_capacity(PACKET_LEN);
    packet.extend_from_slice(nonce);
    packet.extend_from_slice(&ct);
    Some(packet)
}

/// Open a sealed packet. Returns the message, or `None` if the packet is the
/// wrong size, the key is wrong, or it is cover traffic (fails to authenticate).
#[must_use]
pub fn open(key: &[u8; HYBRID_KEY_LEN], packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() != PACKET_LEN {
        return None;
    }
    let (nonce, ct) = packet.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let body = cipher.decrypt(XNonce::from_slice(nonce), ct).ok()?;
    if body.len() != BODY_LEN {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([body[0], body[1]]));
    if len > MAX_MESSAGE_LEN {
        return None;
    }
    Some(body[2..2 + len].to_vec())
}
