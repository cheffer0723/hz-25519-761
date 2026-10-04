//! Prove HZ-25519-761 end to end.
//!
//! INNER  : the hybrid double-lock agrees and breaks if either half is tampered;
//!          seal/open round-trips; a wrong key does not open; packets are fixed size.
//! MIDDLE : the silent handshake confirms holders and stays silent for strangers.
//! OUTER  : a cover decoy is the same size as a real packet and never opens.
//! E2E    : first contact completes with zero content; only then is a message
//!          delivered; an attacker with wrong keys gets silence.

use holdzero::deception::{cover_packet, is_well_formed};
use holdzero::handshake::{proof, verify, ROLE_RECIPIENT, ROLE_SENDER};
use holdzero::protocol::{recipient_accept_hello, sender_hello};
use holdzero::{open, recipient_accept, seal, sender_initiate, HybridMessage, PACKET_LEN};
use sntrup761::{
    generate_key_from_seed, Ciphertext, DecapsulationKey, EncapsulationKey, CIPHERTEXT_SIZE,
};
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};

type RecipientKeys = ([u8; 32], [u8; 32], EncapsulationKey, DecapsulationKey);

/// A recipient's long-term contact keys (seeded for reproducibility).
fn recipient_keys(x_seed: u8, pq_seed: u8) -> RecipientKeys {
    let x_secret = [x_seed; 32];
    let x_public = *XPublic::from(&XSecret::from(x_secret)).as_bytes();
    let (pq_pub, pq_sec) = generate_key_from_seed([pq_seed; 32]);
    (x_secret, x_public, pq_pub, pq_sec)
}

// ---- INNER: hybrid double-lock ---------------------------------------------

#[test]
fn hybrid_both_sides_agree() {
    let (x_sec, x_pub, pq_pub, pq_sec) = recipient_keys(0x11, 0x22);
    let (msg, sender_key) = sender_initiate(&x_pub, &pq_pub, [0x33; 32], [0x44; 32]);
    assert_eq!(sender_key, recipient_accept(&x_sec, &pq_sec, &msg));
}

#[test]
fn hybrid_tampering_the_post_quantum_half_breaks_it() {
    let (x_sec, x_pub, pq_pub, pq_sec) = recipient_keys(0x11, 0x22);
    let (msg, sender_key) = sender_initiate(&x_pub, &pq_pub, [0x33; 32], [0x44; 32]);

    let mut ct = [0u8; CIPHERTEXT_SIZE];
    ct.copy_from_slice(msg.pq_ciphertext.as_ref());
    ct[0] ^= 0xFF;
    let tampered = HybridMessage {
        x_ephemeral_public: msg.x_ephemeral_public,
        pq_ciphertext: Ciphertext::try_from(ct.as_slice()).unwrap(),
    };
    assert_ne!(sender_key, recipient_accept(&x_sec, &pq_sec, &tampered));
}

#[test]
fn hybrid_tampering_the_classical_half_breaks_it() {
    let (x_sec, x_pub, pq_pub, pq_sec) = recipient_keys(0x11, 0x22);
    let (msg, sender_key) = sender_initiate(&x_pub, &pq_pub, [0x33; 32], [0x44; 32]);

    let mut eph = msg.x_ephemeral_public;
    eph[0] ^= 0xFF;
    let tampered = HybridMessage {
        x_ephemeral_public: eph,
        pq_ciphertext: msg.pq_ciphertext,
    };
    assert_ne!(sender_key, recipient_accept(&x_sec, &pq_sec, &tampered));
}

// ---- INNER: content seal ----------------------------------------------------

#[test]
fn seal_open_roundtrips_and_is_fixed_size() {
    let (x_sec, x_pub, pq_pub, pq_sec) = recipient_keys(0x11, 0x22);
    let (msg, key) = sender_initiate(&x_pub, &pq_pub, [0x33; 32], [0x44; 32]);
    let recipient_key = recipient_accept(&x_sec, &pq_sec, &msg);

    let packet = seal(&key, &[0x01; 24], b"hello, dead drop").expect("seal");
    assert_eq!(packet.len(), PACKET_LEN);
    assert_eq!(
        open(&recipient_key, &packet).as_deref(),
        Some(&b"hello, dead drop"[..])
    );
}

#[test]
fn wrong_key_does_not_open() {
    let (_x_sec, x_pub, pq_pub, _pq_sec) = recipient_keys(0x11, 0x22);
    let (_msg, key) = sender_initiate(&x_pub, &pq_pub, [0x33; 32], [0x44; 32]);
    let packet = seal(&key, &[0x01; 24], b"secret").expect("seal");

    let mut wrong = key;
    wrong[0] ^= 0xFF;
    assert_eq!(open(&wrong, &packet), None);
}

#[test]
fn message_too_long_is_refused() {
    let key = [0x09; 32];
    assert_eq!(seal(&key, &[0x01; 24], &vec![0u8; 1000]), None);
}

// ---- MIDDLE: silent handshake ----------------------------------------------

#[test]
fn proof_confirms_for_holder() {
    let key = [0x07; 32];
    let tag = proof(&key, ROLE_SENDER, b"transcript bytes");
    assert!(verify(&key, ROLE_SENDER, b"transcript bytes", &tag));
}

#[test]
fn proof_fails_for_wrong_key_wrong_role_or_tamper() {
    let key = [0x07; 32];
    let tag = proof(&key, ROLE_SENDER, b"transcript bytes");

    let mut wrong_key = key;
    wrong_key[0] ^= 0xFF;
    assert!(!verify(&wrong_key, ROLE_SENDER, b"transcript bytes", &tag));
    assert!(!verify(&key, ROLE_RECIPIENT, b"transcript bytes", &tag));
    assert!(!verify(&key, ROLE_SENDER, b"different transcript", &tag));
}

// ---- OUTER: deception -------------------------------------------------------

#[test]
fn cover_matches_real_size_and_never_opens() {
    let (_x_sec, x_pub, pq_pub, _pq_sec) = recipient_keys(0x11, 0x22);
    let (_msg, key) = sender_initiate(&x_pub, &pq_pub, [0x33; 32], [0x44; 32]);
    let real = seal(&key, &[0x01; 24], b"real message").expect("seal");
    let cover = cover_packet(&[0xAB; 32]);

    assert_eq!(real.len(), cover.len());
    assert!(is_well_formed(&real) && is_well_formed(&cover));
    assert_ne!(real, cover);
    assert_eq!(open(&key, &cover), None);
}

// ---- END TO END -------------------------------------------------------------

#[test]
fn e2e_first_contact_then_message() {
    let (bob_x_sec, bob_x_pub, bob_pq_pub, bob_pq_sec) = recipient_keys(0x11, 0x22);

    let (hello, pending) = sender_hello(&bob_x_pub, &bob_pq_pub, [0x33; 32], [0x44; 32]);
    let (bob_proof, bob_session) =
        recipient_accept_hello(&bob_x_sec, &bob_pq_sec, &hello).expect("Bob confirms Alice");
    let alice_session = pending.confirm(&bob_proof).expect("Alice confirms Bob");

    let packet = alice_session
        .seal(&[0x55; 24], b"meet at the usual drop")
        .expect("seal");
    assert_eq!(packet.len(), PACKET_LEN);
    assert_eq!(
        bob_session.open(&packet).as_deref(),
        Some(&b"meet at the usual drop"[..])
    );
}

#[test]
fn e2e_stranger_gets_silence() {
    let (_bob_x_sec, bob_x_pub, bob_pq_pub, _bob_pq_sec) = recipient_keys(0x11, 0x22);
    let (mallory_x_sec, _m_x_pub, _m_pq_pub, mallory_pq_sec) = recipient_keys(0xEE, 0xDD);

    let (hello, _pending) = sender_hello(&bob_x_pub, &bob_pq_pub, [0x33; 32], [0x44; 32]);
    assert!(recipient_accept_hello(&mallory_x_sec, &mallory_pq_sec, &hello).is_none());
}
