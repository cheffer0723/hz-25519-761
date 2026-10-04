# Contributing

Thanks for looking. This is an experimental cryptography project, so review,
criticism, and independent implementations are especially welcome.

## Ground rules

- **Security issues go private**, never in a public issue or PR — see
  [`SECURITY.md`](SECURITY.md).
- A change to the protocol itself (key derivation, handshake, framing, seal,
  cover) is a **wire-format change**. It must update `docs/SPECIFICATION.md`, and
  the conformance vector (`vectors/hz-25519-761.json`) is regenerated only by a
  deliberate decision — never edited just to make a red test pass.
- Implementations in other languages are encouraged. The specification is
  CC-BY-4.0 and implementing the protocol is royalty-free; you need not adopt the
  reference implementation's AGPL-3.0 license for your own code.

## Reference implementation checks

Run these from `reference/` before opening a PR; CI runs the same:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The crate forbids `unsafe` and denies clippy `all` + `pedantic`. The fuzz targets
in `fuzz/` need a nightly toolchain and `cargo-fuzz`.

## Sign-off

Please sign your commits off (`git commit -s`) to certify the
[Developer Certificate of Origin](https://developercertificate.org/).
