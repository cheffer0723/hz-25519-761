# HZ-25519-761 ("HoldZero") — Protocol Specification

Version 1 · 2026-10-04

Suite identifier: `HOLDZERO-X25519-SNTRUP761-XCHACHA20POLY1305-BLAKE2B`

> **Specification license:** CC-BY-4.0. **Implementing the protocol described
> here is unrestricted and royalty-free**, under any license you choose. (The
> reference *code* in this repository is AGPL-3.0-only; that does not restrict
> independent implementations.)
>
> **Status: experimental.** The primitives are standard; the composition (silent
> handshake, cover traffic) is novel and needs public auditing to increase
> accountability. See `SECURITY.md`.

This document is self-contained: an implementer should be able to produce an
interoperable implementation from it, and check it against
`vectors/hz-25519-761.json`.

## 1. Notation

- `a || b` — concatenation of byte strings.
- `x[i..j]` — bytes `i` (inclusive) to `j` (exclusive), zero-indexed.
- `U16BE(n)` — `n` as a 2-byte big-endian unsigned integer.
- `U64LE(n)` — `n` as an 8-byte little-endian unsigned integer.
- `BLAKE2b(m)` — BLAKE2b with 64-byte (512-bit) output (RFC 7693).
- All multi-byte integers on the wire are as stated; keys and ciphertexts are
  fixed-length byte strings.

## 2. Primitives and parameters

| Role | Primitive | Reference | Sizes (bytes) |
|------|-----------|-----------|---------------|
| Classical key exchange | X25519 | RFC 7748 | public 32, secret 32, shared 32 |
| Post-quantum KEM | Streamlined NTRU Prime (sntrup761) | draft-josefsson-ntruprime-streamlined | public 1158, secret 1763, ciphertext 1039, shared 32 |
| AEAD | XChaCha20-Poly1305 | RFC 8439 + XChaCha extension | key 32, nonce 24, tag 16 |
| Hash / KDF / MAC | BLAKE2b-512 | RFC 7693 | output 64 |

## 3. Constants

```
HYBRID_KEY_LEN   = 32
NONCE_LEN        = 24
BODY_LEN         = 256         # fixed padded plaintext
MAX_MESSAGE_LEN  = 254         # BODY_LEN - 2
PACKET_LEN       = 296         # NONCE_LEN + BODY_LEN + 16 (tag)
TAG_LEN          = 32          # handshake proof length

LABEL       = "dd-hybrid-x25519-sntrup761-v1"   # key derivation
HS_LABEL    = "dd-silent-handshake-v1"          # handshake proof
FILLER_LABEL= "dd-cover-v1"                      # cover expansion

ROLE_SENDER    = 0x01
ROLE_RECIPIENT = 0x02
```

Label strings are ASCII, with no terminator.

## 4. Inner slot — hybrid key agreement

A recipient publishes a **contact public key pair**: an X25519 public key
`R_x` (32 bytes) and an sntrup761 public key `R_pq` (1158 bytes). The recipient
keeps the matching secrets `r_x` and `r_pq`.

### 4.1 Sender

1. Generate an ephemeral X25519 key pair `(e_x, E_x)` (`E_x` is 32 bytes).
2. `x_shared = X25519(e_x, R_x)` (32 bytes).
3. `(C_pq, pq_shared) = sntrup761.Encapsulate(R_pq)` — `C_pq` is 1039 bytes,
   `pq_shared` is 32 bytes.
4. `key = COMBINE(x_shared, pq_shared, E_x, R_x, C_pq)` (§4.3).

The sender's key-agreement message is `HybridMessage = E_x || C_pq`
(32 + 1039 = 1071 bytes). This byte string is the **transcript** `T`.

### 4.2 Recipient

Given `HybridMessage = E_x || C_pq`:

1. `x_shared = X25519(r_x, E_x)`.
2. `pq_shared = sntrup761.Decapsulate(r_pq, C_pq)`.
3. `key = COMBINE(x_shared, pq_shared, E_x, R_x, C_pq)` where `R_x` is the
   recipient's own X25519 public key (derivable from `r_x`).

Both sides now hold the identical `key`.

### 4.3 COMBINE

```
COMBINE(x_shared, pq_shared, E_x, R_x, C_pq) =
    BLAKE2b( LABEL || x_shared || pq_shared || E_x || R_x || C_pq )[0..32]
```

The key depends on both shared secrets and on the full transcript, so altering
either lock's contribution changes the key. **Extension point:** a future third
(experimental) lock is added by folding its shared secret into this hash before
truncation; the two proven locks still gate the key.

## 5. Inner slot — content seal

A message `M` (0 ≤ |M| ≤ `MAX_MESSAGE_LEN`) is sealed under `key` with a 24-byte
`nonce` (unique per key; random in production):

```
body = U16BE(|M|) || M || zeros        # padded to BODY_LEN = 256 bytes
ct   = XChaCha20Poly1305.Seal(key, nonce, body)     # BODY_LEN + 16 bytes
packet = nonce || ct                                # PACKET_LEN = 296 bytes
```

Opening reverses it: split `nonce || ct`, AEAD-open, read `U16BE` length, return
the first `len` bytes. Reject (return nothing) if the packet is not exactly
`PACKET_LEN`, the tag fails, or the length field exceeds `MAX_MESSAGE_LEN`.

Because the plaintext is padded to a fixed size, the true message length never
leaks, and every packet is exactly `PACKET_LEN` of random-looking bytes.

## 6. Middle slot — the silent handshake

A **proof** of key possession, bound to the transcript and to the author's role:

```
PROOF(key, role, T) = BLAKE2b( HS_LABEL || key || role || T )[0..32]
```

`role` is a single byte (`ROLE_SENDER` or `ROLE_RECIPIENT`). Proofs MUST be
compared in **constant time**.

First contact carries no message content:

1. **Sender → Recipient:** `hello = T || PROOF(key, ROLE_SENDER, T)`
   (transcript, then a 32-byte proof; 1071 + 32 = 1103 bytes).
2. **Recipient:** derive `key` (§4.2), recompute `PROOF(key, ROLE_SENDER, T)`
   and compare to the received proof. **If it does not match, abort silently** —
   send nothing. If it matches, reply with `PROOF(key, ROLE_RECIPIENT, T)`.
3. **Sender:** verify `PROOF(key, ROLE_RECIPIENT, T)`. If it matches, the session
   is confirmed.

Only after confirmation does either side seal content (§5) under `key`. A party
that does not hold `key` cannot produce a valid proof, so it receives no reply
and no content is ever exchanged with it.

## 7. Outer slot — cover traffic

A **cover packet** is `PACKET_LEN` bytes expanded from a 32-byte seed with
BLAKE2b in counter mode:

```
cover(seed):
    out = ""
    counter = 0
    while len(out) < PACKET_LEN:
        out ||= BLAKE2b( FILLER_LABEL || seed || U64LE(counter) )
        counter += 1
    return out[0..PACKET_LEN]
```

A real sealed packet (§5) and a cover packet are both `PACKET_LEN` bytes and both
indistinguishable from random to anyone without `key`. A cover packet carries no
message and never opens under any key. (In production the seed is random; the
deterministic expansion exists so the behaviour is testable.)

## 8. Security analysis

The primitives are standard and analysed elsewhere; what is new here is how they
are composed. This section states the model and the rationale so reviewers can
attack the design directly. **It is an argument, not a proof** — a formal
analysis of the handshake is planned, not done, and public review is invited.

### 8.1 Goals

- **Confidentiality and integrity** of message content between a sender who holds
  a recipient's contact keys and that recipient.
- **Hybrid security:** the session key stays secret unless *both* the classical
  and the post-quantum lock are broken, including against a "harvest now, decrypt
  later" adversary who records traffic for a future quantum computer.
- **No reply to a non-holder:** a party that does not hold the shared key learns
  nothing and triggers no content.
- **Indistinguishable cover:** an observer without the key cannot tell a real
  packet from a decoy, or whether a message was sent.

### 8.2 Adversary, and what is out of scope

The in-scope adversary sees and can modify the bytes on the wire and can initiate
contact. **Out of scope:** the transport's view of *who* is connecting — the
sender's network address and the timing of connections. Concealing those is the
transport layer's job (e.g. a mixnet), not this protocol's. Also out of scope:
endpoint compromise, and side channels other than the timing of the proof
comparison (addressed in §8.5).

### 8.3 Why the key binds both locks

`COMBINE` (§4.3) hashes both shared secrets together with `BLAKE2b`. Recovering
the key requires recovering the hash input, which requires *both* `x_shared` (an
X25519 computation) *and* `pq_shared` (an sntrup761 decapsulation). Breaking one
primitive leaves the other's 32 secret bytes still in the hash input. The
transcript (`E_x`, `R_x`, `C_pq`) is also bound in, so a key is tied to the exact
exchange that produced it.

### 8.4 What the silent handshake does and does not give

- It proves **key possession** before any content, so a stranger or an active
  attacker who cannot derive the key cannot elicit a reply or any ciphertext.
- Each proof is bound to the transcript and to the author's **role**, so the two
  proofs cannot be swapped or replayed across roles.
- It is **not** an identity-authentication protocol: it proves "this party holds
  the key derived from these contact keys," not "this party is a specific named
  human." Binding a key to a human identity is the application's job.

### 8.5 Known limitations

- **Novel composition, unproven.** The handshake and cover layers are not
  standard constructions; treat them as experimental until reviewed.
- **Nonce uniqueness is required** (see §9) — it is an implementer obligation,
  not enforced by the format.
- **Single exchange.** This version covers one first-contact exchange and one
  sealed message; a continuous session ratchet is future work.
- **Cover traffic shapes bytes, not behaviour.** Equal-size, random-looking
  packets defeat content/length distinguishing, but a *traffic-analysis*
  adversary watching volume and timing is, again, the transport layer's problem.

## 9. Security considerations (implementer obligations)

- **Hybrid guarantee.** The session key is secure unless *both* X25519 and
  sntrup761 are broken. This is the reason for the construction.
- **Novel composition.** The handshake and cover-traffic layers are not standard
  constructions and need public auditing to increase accountability. Treat them
  as experimental.
- **Nonce uniqueness.** `XChaCha20-Poly1305` requires a unique nonce per key.
  The 24-byte nonce makes random generation safe; reusing a nonce under one key
  breaks confidentiality.
- **Key handling.** The derived key is a session secret. A binding into a host
  application SHOULD keep it out of less-trusted layers (e.g. keep it in the
  implementation language, not a scripting layer).
- **Metadata out of scope.** This protocol does not conceal the sender's network
  address or connection timing. That is the transport layer's responsibility.
- **Forward secrecy.** The sender's X25519 key is ephemeral per exchange; the
  recipient's keys are long-term. This specification covers a single
  first-contact exchange and one sealed message; a full session ratchet is out of
  scope for version 1.

## 10. Conformance

`vectors/hz-25519-761.json` pins fixed inputs and the expected `hello_wire`,
recipient proof, and sealed packet. An implementation is conformant with respect
to this vector when it reproduces those outputs byte for byte and opens the
sealed packet back to the original message. The reference check is
`reference/tests/conformance.rs`.
