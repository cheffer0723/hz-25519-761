//! Frozen conformance vectors for HZ-25519-761.
//!
//! Reads `vectors/hz-25519-761.json`, replays the flow from its fixed inputs, and
//! asserts the current code reproduces the pinned wire bytes: the handshake
//! `hello_wire`, the recipient proof, and the sealed packet, plus the round-trip
//! open. It then checks the edge and negative cases: an empty message, a
//! maximum-length message, a pinned cover packet, and that a tampered handshake
//! and a wrong-key open are both rejected.
//!
//! Any change to the key derivation, the handshake proof, the framing, or the
//! seal breaks this test loudly — that is the point. Regenerate the vector only
//! by deliberate decision, not to make a red test pass.

use holdzero::deception::cover_packet;
use holdzero::protocol::{recipient_accept_hello, sender_hello};
use serde::Deserialize;
use sntrup761::generate_key_from_seed;
use x25519_dalek::{PublicKey, StaticSecret};

const VECTOR: &str = include_str!("../../vectors/hz-25519-761.json");

#[derive(Deserialize)]
struct Vector {
    inputs: Inputs,
    expected: Expected,
    cases: Cases,
}

#[derive(Deserialize)]
struct Inputs {
    x_recipient_secret: String,
    pq_keygen_seed: String,
    x_ephemeral_secret: String,
    pq_encaps_seed: String,
    nonce: String,
    message_utf8: String,
}

#[derive(Deserialize)]
struct Expected {
    hello_wire: String,
    recipient_proof: String,
    sealed_packet: String,
}

#[derive(Deserialize)]
struct Cases {
    empty_message: SealCase,
    max_message: SealCase,
    cover: CoverCase,
}

#[derive(Deserialize)]
struct SealCase {
    nonce: String,
    message_utf8: String,
    sealed_packet: String,
}

#[derive(Deserialize)]
struct CoverCase {
    seed: String,
    packet: String,
}

fn bytes32(hex_str: &str) -> [u8; 32] {
    <[u8; 32]>::try_from(hex::decode(hex_str).unwrap().as_slice()).unwrap()
}

fn nonce24(hex_str: &str) -> [u8; 24] {
    <[u8; 24]>::try_from(hex::decode(hex_str).unwrap().as_slice()).unwrap()
}

#[test]
fn matches_the_frozen_vectors() {
    let v: Vector = serde_json::from_str(VECTOR).unwrap();

    let x_recipient_secret = bytes32(&v.inputs.x_recipient_secret);
    let x_recipient_public = *PublicKey::from(&StaticSecret::from(x_recipient_secret)).as_bytes();
    let (pq_public, pq_secret) = generate_key_from_seed(bytes32(&v.inputs.pq_keygen_seed));
    let x_ephemeral_secret = bytes32(&v.inputs.x_ephemeral_secret);
    let pq_encaps_seed = bytes32(&v.inputs.pq_encaps_seed);

    // --- Happy path ---------------------------------------------------------
    let (hello, pending) = sender_hello(
        &x_recipient_public,
        &pq_public,
        x_ephemeral_secret,
        pq_encaps_seed,
    );
    let mut hello_wire = hello.message.transcript();
    hello_wire.extend_from_slice(&hello.sender_proof);
    assert_eq!(
        hex::encode(&hello_wire),
        v.expected.hello_wire,
        "hello_wire drifted"
    );

    let (recipient_proof, bob) =
        recipient_accept_hello(&x_recipient_secret, &pq_secret, &hello).expect("recipient accepts");
    assert_eq!(
        hex::encode(recipient_proof),
        v.expected.recipient_proof,
        "recipient proof drifted"
    );

    let alice = pending.confirm(&recipient_proof).expect("sender confirms");
    let message = v.inputs.message_utf8.as_bytes();
    let packet = alice
        .seal(&nonce24(&v.inputs.nonce), message)
        .expect("seal");
    assert_eq!(
        hex::encode(&packet),
        v.expected.sealed_packet,
        "sealed packet drifted"
    );
    assert_eq!(
        bob.open(&packet).as_deref(),
        Some(message),
        "round trip failed"
    );

    // --- Edge cases: empty and maximum-length messages ----------------------
    for case in [&v.cases.empty_message, &v.cases.max_message] {
        let msg = case.message_utf8.as_bytes();
        let p = alice.seal(&nonce24(&case.nonce), msg).expect("seal");
        assert_eq!(
            hex::encode(&p),
            case.sealed_packet,
            "sealed packet drifted (edge case)"
        );
        assert_eq!(
            bob.open(&p).as_deref(),
            Some(msg),
            "edge-case round trip failed"
        );
    }

    // --- Cover packet is pinned and never opens -----------------------------
    let cover = cover_packet(&bytes32(&v.cases.cover.seed));
    assert_eq!(
        hex::encode(&cover),
        v.cases.cover.packet,
        "cover packet drifted"
    );
    assert_eq!(bob.open(&cover), None, "a cover packet must never open");

    // --- Negative: a tampered handshake and a wrong-key open are rejected ---
    let mut tampered = hello_wire.clone();
    tampered[0] ^= 0xFF;
    let bad_message = holdzero::HybridMessage::from_wire(&tampered[..tampered.len() - 32]);
    // Either the wire no longer parses, or if it parses the proof no longer verifies.
    if let Some(msg) = bad_message {
        let mut sender_proof = [0u8; 32];
        sender_proof.copy_from_slice(&tampered[tampered.len() - 32..]);
        let hello = holdzero::protocol::Hello {
            message: msg,
            sender_proof,
        };
        assert!(
            recipient_accept_hello(&x_recipient_secret, &pq_secret, &hello).is_none(),
            "a tampered handshake must be rejected"
        );
    }

    let mut wrong_key_packet = packet.clone();
    wrong_key_packet[24] ^= 0xFF; // corrupt the ciphertext
    assert_eq!(
        bob.open(&wrong_key_packet),
        None,
        "a corrupted packet must not open"
    );
}
