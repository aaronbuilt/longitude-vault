# Longitude Vault

The open file format for [Longitude](https://longitude.money) — your wealth
in a file you own.

A **vault** is the complete record of a financial life: accounts, holdings,
balance history, life-design scenarios, and your overrides of world-data
assumptions. It lives on your machine as human-readable, diffable TOML, and
its encrypted form is a standard [age](https://age-encryption.org/v1) file:

```
vault.lon = age( zstd( tar( TOML documents ) ) )
```

Data liberation is **normative, not incidental** — a vault must always be
fully recoverable with stock tools and no Longitude software:

```sh
age -d -i identity.txt vault.lon | zstd -d | tar -x
```

If Longitude the company disappears, you keep the spec, your file, and this
repo.

## Contents

- [`SPEC.md`](SPEC.md) — the vault format specification, v0.1 (draft)
- [`crates/longitude-vault`](crates/longitude-vault) — reference library
  (Rust): load, validate per §8, pack/unpack with the §5.4
  untrusted-container rules enforced while streaming
- [`crates/longitude-cli`](crates/longitude-cli) — the `longitude` CLI:
  `vault init | check | pack | unpack | export`
- [`fixtures/`](fixtures) — conformance test vectors: the §9 reference vault
  in both physical forms, plus hostile containers (path traversal, symlinks,
  duplicate entries, a decompression bomb) that a conforming reader MUST
  reject. See [`fixtures/README.md`](fixtures/README.md).

## The CLI

```sh
cargo install --git https://github.com/aaronbuilt/longitude-vault longitude-cli

longitude vault init my.lonvault --demo      # the SPEC §9 example vault
longitude vault check my.lonvault            # validate (§8) — works on .lon too
age-keygen -o identity.txt                   # keys are plain age keys
longitude vault pack my.lonvault -o vault.lon -i identity.txt
longitude vault unpack vault.lon -o restored -i identity.txt
longitude vault export my.lonvault -o handoff.lon   # passphrase-only (§6.4)
```

The deterministic single-scenario projection (`longitude project`) is the
next piece; it lands in this repo when the engine core does.

CI includes a job that opens the conformance vault with **stock `age`,
`zstd`, and `tar` only** and diffs it against the plaintext form — the
data-liberation guarantee, continuously tested.

## Status

Spec: draft **v0.1 rev 4** (2026-07-04). Reference implementation:
**v0.1.0** — validation, both physical forms, §5.4 hardening, conformance
fixtures. The format is young and feedback is welcome — open an issue for
anything from a typo to a hole in the threat model (§5.4/§6.5 of the spec
are the security-relevant parts and have had one hardening pass).

## License

- The specification (`SPEC.md`) is licensed under
  [CC BY 4.0](LICENSE-SPEC).
- Code in this repository is dual-licensed under
  [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you shall be dual-licensed as above,
without any additional terms or conditions.

---

Made in Detroit · 83.0458° W
