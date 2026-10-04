# Testing

The risk in HZ-25519-761 is not the primitives — X25519, sntrup761,
XChaCha20-Poly1305 and BLAKE2b are standard and tested by their own projects — it
is the **composition** (the hybrid key derivation, the silent handshake, the
framing, the cover layer). Testing is aimed there.

## What runs, and where

| What | How | Status |
|------|-----|--------|
| **Conformance vectors** — fixed inputs → exact `hello_wire`, recipient proof, sealed packet, plus empty-message, max-length, and cover cases | `reference/tests/conformance.rs` against `vectors/hz-25519-761.json` | ✅ runs in CI on every push/PR |
| **Negative cases** — tampered handshake rejected, wrong-key / corrupted packet does not open, cover never opens | `reference/tests/conformance.rs` | ✅ CI |
| **Protocol behaviour** — hybrid agreement, breaking either lock changes the key, seal/open round-trip, over-long message refused, handshake confirms for holders and stays silent for strangers, cover indistinguishable in size/shape | `reference/tests/protocol.rs` (11 tests) | ✅ CI |
| **Constant-time proof comparison** | `subtle::ConstantTimeEq` in the handshake verify | ✅ in code |
| **Fuzzing (totality)** — `open` and the wire parser must never panic on hostile input | `fuzz/` (libFuzzer) | ✅ scheduled nightly in CI; run locally with `cargo +nightly fuzz run` |

## What is deliberately **not** done here

- **Re-testing the primitives.** Their known-answer tests live upstream; repeating
  them here adds little. (The hybrid construction over them *is* pinned, above.)
- **Formal protocol analysis** (e.g. a Tamarin/ProVerif model of the handshake).
  This is the right next step for a novel composition and is **planned**, not yet
  done.
- **Independent / third-party audit.** Not yet done — public review is invited;
  see [`SECURITY.md`](SECURITY.md).

## Running it

```bash
cargo test   --manifest-path reference/Cargo.toml     # vectors + negative + protocol
cargo clippy --manifest-path reference/Cargo.toml --all-targets -- -D warnings
cargo fmt    --manifest-path reference/Cargo.toml --check
cargo +nightly fuzz run holdzero_open                 # from fuzz/ ; also holdzero_wire
```

## Changing the protocol

A change to the key derivation, handshake, framing, seal, or cover is a
wire-format change: update `docs/SPECIFICATION.md` and regenerate
`vectors/hz-25519-761.json` by deliberate decision. Never edit a vector just to
make a red test pass.
