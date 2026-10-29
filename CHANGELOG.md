# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-10-29 (README edit finished 21:32:26 UTC)

### Added
 - Added some depth towards the end with some serious inner style questions for a user to ask his or herself maybe during inner dialogue at first. How do these questions or statements make you feel deep inside? These type of “HARDER to ask one of your fellow human beings” Questions. You know the type.
   
 - How does each question make you, Right now as you, (like much of us) try your best to get to your next day off.
   
 - Our current state of affairs?

 - How about in the Mass consciousness of ALL of US, is beginning to have similarities,(maybe déjà vu)

 - Why seemingly to be happening all at once, of you and me - the regular 40-60 hour or more work week, still barely enough to be just a **Surviving** American citizen.

 - Have a look at the **Hard** internal questions and try to really understand what’s happening to your emotional state as you read them.

 - Maybe you’ll write each down on a Sheet of paper so you can look at the same question tomorrow.

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
