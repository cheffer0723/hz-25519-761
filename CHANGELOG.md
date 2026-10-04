# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
