# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-10-29

### Added
- `AUTHOR.md`: "A word from the author", moved out of the README into its own
  file. The README links to it.
- README: sources for the claims in "Why this method?" (Dual_EC_DRBG, the NSA's
  role in the post-quantum selection, the NSA QUANTUM servers and AT&T's Room
  641A), and a note that none of HoldZero's building blocks is a NIST design.

## [0.1.1] - 2026-10-29

### Added
- README: "Why this method?" (why not to rely on NIST standards alone, and six
  reasons for Tor), "Test it", "Testing" (Dead Drop's 417 automatic tests), and
  "A word from the author".
- Harder, inner questions for the reader to ask themselves, perhaps first in
  their own inner dialogue. How does each one make you feel deep inside, right
  now, as you (like most of us) try your best to reach your next day off?
- Our current state of affairs: why it seems to be happening to all of us at
  once, almost like déjà vu in the mass consciousness, and why a regular 40 to
  60 hour work week is still barely enough to just **survive** as an American
  citizen.
- An invitation to notice what happens to your emotional state as you read the
  **hard** questions, and perhaps to write each one down on a sheet of paper so
  you can look at the same question tomorrow.

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
