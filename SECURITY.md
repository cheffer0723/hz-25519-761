# Security Policy

## Status: experimental — needs public auditing to increase accountability

HZ-25519-761 is published openly for review and criticism. The primitives it uses
(X25519, sntrup761, XChaCha20-Poly1305, BLAKE2b) are well-studied, but the way
this protocol **composes** them — the silent handshake and the cover-traffic
layer — is novel and **needs public auditing** to increase accountability. Public
scrutiny is invited. **Do not rely on it to protect anyone who could be harmed if
it fails.**

## What it protects, and what it does not

- Protects: the confidentiality and integrity of message content, and of the
  first-contact handshake; a key secure unless *both* the classical and the
  post-quantum lock are broken.
- Does **not** protect: transport metadata — your IP address and the timing of
  your connection. Concealing those is the transport layer's job (e.g. a mixnet),
  not this protocol's.

## Reporting a vulnerability

Please report security issues **privately**, not in public issues or pull
requests. Use GitHub's private vulnerability reporting on this repository
(the **Security** tab → **Report a vulnerability**).

Please include enough detail to reproduce (affected version/commit, and a
concrete scenario). We will acknowledge the report, work on a fix, and credit you
unless you prefer otherwise.

## Scope

In scope: the specification (`docs/`), the reference implementation
(`reference/`), the conformance vector, and the fuzz targets. Weaknesses in the
underlying primitives belong upstream with those projects.
