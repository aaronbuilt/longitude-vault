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
- `cli/` — the open-source reference CLI (Rust): validate, pack/unpack,
  deterministic single-scenario projection. **Coming; will live in this repo.**
- `fixtures/` — conformance test vectors (valid vaults, malicious containers,
  decimal-grammar edge cases). Arriving with the CLI.

## Status

Draft **v0.1 rev 4** (2026-07-04). The format is young and feedback is
welcome — open an issue for anything from a typo to a hole in the threat
model (§5.4/§6.5 of the spec are the security-relevant parts and have had
one hardening pass).

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
