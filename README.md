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

## Why this method?

If you just do one brief and fast google searches for NIST standards, and why that "Gold standard" of cryptography 
is riddled with vulnerabilities. And this is data that is publicly available and known. How many Zero Day exploits 
are there filed away on servers in Virginia for a rainy day? Why TOR? Simply the pipework delivery that is needed 
for actual real start to finish- 

1. The relays can't see your address

2. No server of our own to attack or subpoena

3. Your trips can't be linked together

4. Your internet provider can't tell who you talk to, (nor can the secret server rack that ALL providers put a few ms faster
than that website you typed the address into the bar thinking you were being served). 

5. It's proven and open. Tor has been attacked by experts for over 20 years (plus, built by spies, for spies to use. it's in interest of spies
to keep secrets hidden by this method)

6. It's built into the app. People don't install a separate Tor app. 

## Please feel free to test as much of this for vulnerabilities as you humanly and or "agentically" can here ——-> vectors/hz-25519-761.json

## Testing 

**To normal users**

-Dead Drop is checked by 417 automatic tests that make sure the encryption, the network 
and the app all do what they should.

**The professional cryptographer**

-370 app tests (TypeScript, 40 test files) in scripts folder. (plain English naming)

-47 core-engine tests (Rust, 13 files) in modules/<engine>/rust/. Run commands, like npm run test:vault, are listed in package.json.

**All of these testing locations are in the Dead Drop private repo**  

**What?**

 **Think intellectual property should be visible too?**

Too bad, so sad. You can build a better version. 

**So………Why haven't you?**

## Long overdue.

**Frog in pot theory?**

## It will seem too inconvenient to just begin. This is by design. 


## Priceless, is the individuality of my children. 


## Priceless, will be the individuality of their children.

## Priceless is YOUR individuality. 

**IMPORTANT- The breaking of our will started decades ago**

## Will you join me?
.
.
.
. 
.
.
## Take a STAND. This is YOUR God Damned nation. 


## This is the UNITED STATES of AMERICA. 


**There will always be MORE slaves, than there are Masters, we have been trained for this to stay INVISIBLE to YOU and ME**

## Does this language, or final statements Anger you to be asked Questions like these? 


## Apology up front

**This is hard to ponder**

-If these “Philosophical Questions” about our children piss you off to be asked them,  or does asking yourselves these hard questions, internally make you feel less than? This is actually a watchable and measurable occurrence nowadays- to witness children start school these days, and light is visibly leaving each of them more and more every year they age.

**Why?**

**That is yours to answer. Will you?**

