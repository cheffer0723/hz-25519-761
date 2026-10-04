//! The three slots, wired into one flow.
//!
//! First contact (no content yet):
//! 1. Sender runs the INNER key agreement against the recipient's contact keys,
//!    deriving the hybrid key, and attaches its MIDDLE-slot proof.
//! 2. Recipient re-derives the key and verifies the sender's proof. On failure it
//!    returns `None` — silence, no reply, no content. On success it returns its
//!    own proof.
//! 3. Sender verifies the recipient's proof. Both sides are now confirmed and
//!    share a key, with no content sent yet.
//!
//! Then content: either side seals a message under the shared key (INNER part 2);
//! the OUTER slot keeps it a fixed-size, random-looking packet.

use sntrup761::{DecapsulationKey, EncapsulationKey};

use crate::handshake::{self, ROLE_RECIPIENT, ROLE_SENDER, TAG_LEN};
use crate::{recipient_accept, seal, sender_initiate, HybridMessage, HYBRID_KEY_LEN, NONCE_LEN};

/// A confirmed session: both sides proved they hold this key.
pub struct Session {
    key: [u8; HYBRID_KEY_LEN],
}

impl Session {
    /// Seal a message to the confirmed peer. Fixed-size packet out, or `None` if
    /// the message is too long.
    #[must_use]
    pub fn seal(&self, nonce: &[u8; NONCE_LEN], message: &[u8]) -> Option<Vec<u8>> {
        seal(&self.key, nonce, message)
    }

    /// Open a packet from the confirmed peer. `None` for a wrong key or cover.
    #[must_use]
    pub fn open(&self, packet: &[u8]) -> Option<Vec<u8>> {
        crate::open(&self.key, packet)
    }
}

/// What the sender sends on first contact: the key-agreement message plus a proof
/// of key possession. No content rides along.
pub struct Hello {
    /// The hybrid key-agreement message.
    pub message: HybridMessage,
    /// The sender's proof that it holds the derived key.
    pub sender_proof: [u8; TAG_LEN],
}

/// The sender's half-open state: waiting for the recipient's proof back.
pub struct PendingSender {
    key: [u8; HYBRID_KEY_LEN],
    transcript: Vec<u8>,
}

impl PendingSender {
    /// Sender step 3: verify the recipient's proof. `None` means not confirmed
    /// (silence).
    #[must_use]
    pub fn confirm(self, recipient_proof: &[u8; TAG_LEN]) -> Option<Session> {
        if handshake::verify(&self.key, ROLE_RECIPIENT, &self.transcript, recipient_proof) {
            Some(Session { key: self.key })
        } else {
            None
        }
    }
}

/// Sender step 1: build the first-contact `Hello` and hold a pending session.
#[must_use]
pub fn sender_hello(
    x_recipient_public: &[u8; 32],
    pq_recipient_public: &EncapsulationKey,
    x_ephemeral_secret: [u8; 32],
    pq_seed: [u8; 32],
) -> (Hello, PendingSender) {
    let (message, key) = sender_initiate(
        x_recipient_public,
        pq_recipient_public,
        x_ephemeral_secret,
        pq_seed,
    );
    let transcript = message.transcript();
    let sender_proof = handshake::proof(&key, ROLE_SENDER, &transcript);
    (
        Hello {
            message,
            sender_proof,
        },
        PendingSender { key, transcript },
    )
}

/// Recipient step 2: re-derive the key, verify the sender's proof. On success,
/// return the recipient's proof and a confirmed session. On failure, `None` —
/// the recipient stays silent and no content is ever exchanged.
#[must_use]
pub fn recipient_accept_hello(
    x_recipient_secret: &[u8; 32],
    pq_recipient_secret: &DecapsulationKey,
    hello: &Hello,
) -> Option<([u8; TAG_LEN], Session)> {
    let key = recipient_accept(x_recipient_secret, pq_recipient_secret, &hello.message);
    let transcript = hello.message.transcript();
    if !handshake::verify(&key, ROLE_SENDER, &transcript, &hello.sender_proof) {
        return None;
    }
    let recipient_proof = handshake::proof(&key, ROLE_RECIPIENT, &transcript);
    Some((recipient_proof, Session { key }))
}
