# HZ-25519-761 ("HoldZero") — Protocol Specification

Version 1 · 2026-10-04 · §6.1, §6.2 and §11 added 2026-10-18

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

**Randomness.** `e_x` and the encapsulation randomness MUST come from a
cryptographically secure random source. The reference implementation takes both
as 32-byte seeds supplied by the caller (`sender_initiate`, using sntrup761's
deterministic encapsulation), so the host application chooses the random source
and the conformance vectors are reproducible. A caller MUST NOT reuse a seed.

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
and no content is ever exchanged with it. (§6.2 describes one deliberate,
opt-in exception: content riding with the hello itself.)

### 6.1 Bound reply (optional)

A recipient often sends something back together with its proof, for example a
fresh public key to start a message ratchet. The **bound reply** makes the
proof cover that value too, so it cannot be swapped in transit:

```
BOUND(T, b) = T || U16BE(len(b)) || b
```

- **Recipient:** after verifying the sender's proof exactly as in step 2 above,
  reply with `PROOF(key, ROLE_RECIPIENT, BOUND(T, b))` and send `b` alongside it.
- **Sender:** confirm by verifying `PROOF(key, ROLE_RECIPIENT, BOUND(T, b))` for
  the `b` it received. If it does not verify, the sender MUST keep waiting
  (silence) rather than abandon the handshake: a forged reply must not be able
  to cancel the real one.

`b` MUST be at most 65,535 bytes. The sender's proof (step 1) is unchanged.

### 6.2 Labelled secrets

The handshake key is never used directly for anything outside this protocol.
An application that needs its own secrets derives one per purpose, each with
its own label:

```
DERIVE(key, label, context) =
    BLAKE2b( U8(len(label)) || label || key || context )[0..32]
```

`label` is ASCII, 1 to 255 bytes; `context` is any byte string (often empty).
Different labels give unrelated secrets, and none of them equals `key`, so a
derived secret can never be mistaken for a handshake proof or for another
derived secret.

- **After confirmation:** both sides use `DERIVE(key, label, context)`.
- **Before confirmation (content riding with the hello):** both sides use
  `DERIVE(key, label, T || context)`, mixing in the hello's transcript so the
  secret belongs to this one hello. The recipient computes it only after the
  sender's proof has verified; if the proof fails it derives nothing.

**Trade-off of riding with the hello.** Content sealed under a pre-confirmation
secret is protected only by the recipient's long-term keys (plus the sender's
one-time ephemeral key). It is not forward secret against a later theft of the
recipient's long-term keys, and the sender has not yet heard from the recipient.
An application chooses when that trade is acceptable.

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
- **Single exchange.** This protocol covers one first-contact exchange and one
  sealed message. A continuous message ratchet is left to the application, which
  can seed it from a labelled secret (§6.2) and bind its first public key with a
  bound reply (§6.1); §11 describes one that does.
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
  scope for version 1 (see §6.2 and §11 for how an application adds one).
- **Pre-confirmation content** (§6.2) is not forward secret. Use it only where
  the application has decided that trade is acceptable.

## 10. Conformance

`vectors/hz-25519-761.json` pins fixed inputs and the expected `hello_wire`,
recipient proof, and sealed packet. An implementation is conformant with respect
to this vector when it reproduces those outputs byte for byte and opens the
sealed packet back to the original message. The vector's `bound_and_derived`
case pins the bound reply (§6.1) and the labelled secrets (§6.2), both before
and after confirmation, and requires that a changed binding is refused. The
reference check is `reference/tests/conformance.rs`.

## 11. In use: Dead Drop

Dead Drop (an iPhone messenger, in TestFlight beta) uses this protocol for
first contact. It is described here so reviewers can see exactly which parts it
uses and what it builds on top. The labels below are the ones in the vector's
`bound_and_derived` case.

**Used as specified:** the hybrid key agreement (§4), the silent handshake (§6)
with a bound reply (§6.1), and labelled secrets (§6.2). The phone's own secure
random source supplies `e_x` and the encapsulation seed.

**Not used:** the 296-byte content seal (§5) and the cover packets (§7). Dead
Drop has its own fixed packet size and seals its notes itself, as follows.

- **Every packet is exactly 1,991 bytes**, whatever it carries.
- **Hello** (first byte 5): `0x05 || hello (1,103 bytes) || nonce (24) ||
  XChaCha20-Poly1305(k_h, nonce, padded blob, aad = 0x05 || hello)`, where
  `k_h = DERIVE(key, "dd-hz-hello-seal-v1", T)`, the pre-confirmation form.
  The blob carries the sender's contact code and, only when the two people met
  and scanned each other's code in person, a first note.
- **Reply** (first byte 6): `0x06 || nonce (24) || XChaCha20-Poly1305(k_r,
  nonce, padded blob, aad = 0x06)`, where `k_r = DERIVE(key,
  "dd-hz-reply-seal-v1", T)`. The blob carries the recipient's fresh ratchet
  public key `b` and the bound proof `PROOF(key, ROLE_RECIPIENT, BOUND(T, b))`.
- **Every note after that** (first byte 4) rides a Double Ratchet with
  encrypted headers (X25519, XChaCha20-Poly1305, BLAKE2b), seeded on both sides
  from `DERIVE(key, "dd-hz-ratchet-seed-v1", "")` after confirmation, and
  starting from the bound key `b`. Every note gets its own key.

The ratchet, the 1,991-byte framing and how packets travel are Dead Drop's
own; they are outside this specification and are not covered by its vectors.

