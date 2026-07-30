# Fuzzing

`tests/robustness.rs` runs deterministic sweeps on every `cargo test` and covers
the obvious malformation classes. These targets are for coverage-guided
campaigns, which explore far deeper.

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run decoders
cargo +nightly fuzz run frame_reader
```

Nightly is required by libFuzzer, not by the proxy itself.

Every decoder reached here parses bytes from an unauthenticated peer, so a panic
found by these targets is a real, remotely reachable bug. Two were found this
way already: a shift overflow in the async VarInt reader, and unbounded
decompression in the compressed frame path.
