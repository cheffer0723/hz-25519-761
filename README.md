# HZ-25519-761 ("HoldZero")

A hybrid, post-quantum messaging handshake and sealing protocol: a classical and
a post-quantum lock combined so a message is safe unless **both** are broken, a
**silent handshake** so a stranger who can't prove key possession gets no reply
and no content, and a **cover-traffic** layer so a real packet is
indistinguishable from a decoy.

Suite: `HOLDZERO-X25519-SNTRUP761-XCHACHA20POLY1305-BLAKE2B`

Project home: [asymmetria.io](https://asymmetria.io)

---

## ⚠️ Status — experimental; needs public auditing to increase accountability

**Do not use this to protect anyone who could be harmed if it fails.** The
underlying primitives (X25519, sntrup761, XChaCha20-Poly1305, BLAKE2b) are
well-studied, but the way this protocol *composes* them — the silent handshake
and the cover-traffic layer — is **novel and needs public auditing**. This
repository is published openly for exactly that — review, implementation, and
criticism — to increase accountability. It is not yet ready for production
deployment. See [`SECURITY.md`](SECURITY.md).

---

## The three slots

A message is built as nested envelopes with named, swappable slots:

1. **Inner — the locks.** An `X25519` key exchange and an `sntrup761`
   (Streamlined NTRU Prime) encapsulation are folded together with `BLAKE2b`
   into one key. Break the classical half with a quantum computer and the
   post-quantum half still holds; find a weakness in the post-quantum half and
   the classical half still holds. Neither alone is enough. The derived key then
   seals a fixed-size message with `XChaCha20-Poly1305`.
2. **Middle — the silent handshake.** Before any content exists, each side proves
   it holds the shared key with a short constant-time `BLAKE2b` MAC. A non-holder
   cannot produce the proof, so they get silence — nothing to intercept.
3. **Outer — cover traffic.** A real sealed packet is a fixed 296 bytes and looks
   random, so a decoy of the same size and shape is indistinguishable from it to
   anyone without the key.

The full construction is specified in [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md).

## What this protocol does **not** do

It secures the *content and the handshake*. It does **not** hide transport-level
metadata — your IP address and the timing of your connection are the transport
layer's job (for example, a mixnet), not this protocol's.

## Layout

```
docs/SPECIFICATION.md     the protocol specification (implement from this)
reference/                the Rust reference implementation
vectors/hz-25519-761.json frozen known-answer conformance vectors (+ edge/negative cases)
fuzz/                     libFuzzer totality targets for the parsers
TESTING.md                what is tested, what is planned, how to run it
```

Testing is aimed at the composition, not the primitives (which are tested
upstream) — see [`TESTING.md`](TESTING.md) and the security analysis in the spec.

## Quickstart

```bash
# reference implementation: tests, lints, format
cargo test   --manifest-path reference/Cargo.toml
cargo clippy --manifest-path reference/Cargo.toml --all-targets
cargo fmt    --manifest-path reference/Cargo.toml --check

# fuzzing (needs a nightly toolchain + cargo-fuzz)
cargo +nightly fuzz run holdzero_open   # from fuzz/
```

## Licensing

Two different licenses, on purpose:

- **The reference implementation** (`reference/`, `fuzz/`) is licensed
  **AGPL-3.0-only** — see [`LICENSE`](LICENSE). If you run a modified version as a
  network service, you must publish your changes.
- **The specification** (`docs/`) is licensed **CC-BY-4.0**, and **implementing
  the protocol it describes is unrestricted and royalty-free.** Write your own
  implementation under any license you like. We want many implementations.

## A note on the name

`hz-25519-761` is the precise, descriptive name: `25519` is the classical lock
(`X25519`), `761` is the post-quantum lock (`sntrup761`). "HoldZero" is the
informal name for the same protocol.

## Acknowledgments

HZ-25519-761 was designed and directed by Critical Mass Labs. The specification,
the reference implementation, and the conformance and fuzz test suites were
developed in collaboration with Claude (Anthropic's Claude Code), under the
author's direction — every design decision was made and reviewed by the author.
