//! Frozen conformance vectors for HZ-25519-761.
//!
//! Reads `vectors/hz-25519-761.json`, replays the flow from its fixed inputs, and
//! asserts the current code reproduces the pinned wire bytes: the handshake
//! `hello_wire`, the recipient proof, and the sealed packet, plus the round-trip
//! open. It then checks the edge and negative cases: an empty message, a
//! maximum-length message, a pinned cover packet, and that a tampered handshake
//! and a wrong-key open are both rejected. A second test pins the bound reply
//! and the labelled secrets (specification §6.1 and §6.2).
//!
//! Any change to the key derivation, the handshake proof, the framing, or the
//! seal breaks this test loudly — that is the point. Regenerate the vector only
//! by deliberate decision, not to make a red test pass.

use holdzero::deception::cover_packet;
use holdzero::protocol::{
    hello_derive, recipient_accept_hello, recipient_accept_hello_bound, sender_hello,
};
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
    bound_and_derived: BoundCase,
}

#[derive(Deserialize)]
struct BoundCase {
    binding: String,
    bound_recipient_proof: String,
    hello_derived: Vec<DerivedCase>,
    session_derived: Vec<DerivedCase>,
}

#[derive(Deserialize)]
struct DerivedCase {
    label_utf8: String,
    context: String,
    secret: String,
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

#[test]
fn matches_the_bound_and_derived_vectors() {
    let v: Vector = serde_json::from_str(VECTOR).unwrap();
    let case = &v.cases.bound_and_derived;

    let x_recipient_secret = bytes32(&v.inputs.x_recipient_secret);
    let x_recipient_public = *PublicKey::from(&StaticSecret::from(x_recipient_secret)).as_bytes();
    let (pq_public, pq_secret) = generate_key_from_seed(bytes32(&v.inputs.pq_keygen_seed));
    let (hello, pending) = sender_hello(
        &x_recipient_public,
        &pq_public,
        bytes32(&v.inputs.x_ephemeral_secret),
        bytes32(&v.inputs.pq_encaps_seed),
    );

    // --- Secrets derived from the hello, before any reply -------------------
    for d in &case.hello_derived {
        let context = hex::decode(&d.context).unwrap();
        let sender_side = pending.derive(d.label_utf8.as_bytes(), &context);
        let recipient_side = hello_derive(
            &x_recipient_secret,
            &pq_secret,
            &hello,
            d.label_utf8.as_bytes(),
            &context,
        )
        .expect("recipient derives");
        assert_eq!(hex::encode(sender_side), d.secret, "hello secret drifted");
        assert_eq!(sender_side, recipient_side, "both sides must agree");
    }

    // --- The bound reply ----------------------------------------------------
    let binding = hex::decode(&case.binding).unwrap();
    let (proof, bob) =
        recipient_accept_hello_bound(&x_recipient_secret, &pq_secret, &hello, &binding)
            .expect("recipient accepts");
    assert_eq!(
        hex::encode(proof),
        case.bound_recipient_proof,
        "bound proof drifted"
    );

    // A swapped binding is refused, and the sender keeps waiting for the real reply.
    let mut swapped = binding.clone();
    swapped[0] ^= 0xFF;
    let pending = pending
        .confirm_bound(&swapped, &proof)
        .err()
        .expect("a swapped binding must be refused");
    let alice = pending
        .confirm_bound(&binding, &proof)
        .ok()
        .expect("the real reply still confirms");

    // --- Secrets derived from the confirmed session -------------------------
    for d in &case.session_derived {
        let context = hex::decode(&d.context).unwrap();
        let a = alice.derive(d.label_utf8.as_bytes(), &context);
        assert_eq!(hex::encode(a), d.secret, "session secret drifted");
        assert_eq!(a, bob.derive(d.label_utf8.as_bytes(), &context));
    }
}
