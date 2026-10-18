# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Bound reply** (`docs/SPECIFICATION.md` §6.1): the recipient's proof can also
  cover a value sent back with it, such as a fresh ratchet key, so it cannot be
  swapped in transit. A reply that fails to verify leaves the sender waiting
  rather than ending the handshake. Reference: `recipient_accept_hello_bound`,
  `PendingSender::confirm_bound`.
- **Labelled secrets** (§6.2): one secret per named purpose, derived from the
  handshake key, after confirmation (`Session::derive`) or for content riding
  with the hello (`PendingSender::derive`, `hello_derive`), with the
  forward-secrecy trade of the latter stated.
- §4.1 states where the randomness comes from: the caller supplies both seeds.
- §11 describes how Dead Drop uses the protocol and what it builds on top.
- Conformance case `bound_and_derived` in `vectors/hz-25519-761.json`, checked
  by `reference/tests/conformance.rs`, including a swapped-binding refusal.

These are additions only. Every value pinned in 0.1.0 is unchanged.

## [0.1.0] - 2026-10-04

Initial public release — **experimental; needs public auditing to increase accountability**.

### Added
- Protocol specification (`docs/SPECIFICATION.md`), suite
  `HOLDZERO-X25519-SNTRUP761-XCHACHA20POLY1305-BLAKE2B`.
- Rust reference implementation (`reference/`): hybrid X25519 + sntrup761 key
  agreement, fixed-size XChaCha20-Poly1305 content seal, silent handshake, and
  cover traffic.
- Frozen conformance vectors (`vectors/hz-25519-761.json`): the happy path plus
  empty-message, maximum-length, cover-packet, and negative (tampered-handshake,
  wrong-key) cases, all pinned by `reference/tests/conformance.rs`.
- Security analysis in the specification (threat model, rationale, known
  limitations).
- `TESTING.md` describing what is tested, what is deliberately out of scope, and
  what is planned (formal analysis, external audit).
- libFuzzer totality targets for the delivered-packet and wire parsers (`fuzz/`),
  run on a daily schedule via CI (`.github/workflows/fuzz.yml`).
