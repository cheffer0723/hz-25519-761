# Contributing

Thanks for looking. This is an, “experimental” or a better word is maybe “Novel” cryptography project that is used in an active iOS native application Called “Dead Drop - Hold Zero” and is live and available for download using the public link that can be shared and passed with others that you trust. link to public TestFlight download of the beta app version is here -  
https://testflight.apple.com/join/KZcgDpPF

## Important Distinction 

**The cryptological primitives used are not experimental. These are well known standards. What is in need of testing from the public surface is the method and means Hold Zero uses established cryptography primitives. So please, if you feel the drive to maybe test your skill and break/attack something, make sure to criticize annd explain anny success in the open or privately, your call. Crowd level participation and collab welcomes independent implementation in private test lab you use for threat level style work, pitch an idea to the admins and or throw it up in the discussion area. Experiments are especially interesting and welcomed. 

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
