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

- [`SPEC.md`](SPEC.md) — the vault format specification, v0.1
- [`crates/longitude-vault`](crates/longitude-vault) — reference library
  (Rust): load, validate per §8, pack/unpack with the §5.4
  untrusted-container rules enforced while streaming
- [`crates/longitude-engine`](crates/longitude-engine) — the open engine
  core: deterministic single-scenario projection (current-state valuation,
  demand-driven monthly loop, FI date, Longitude Score)
- [`crates/longitude-cli`](crates/longitude-cli) — the `longitude` CLI:
  `keygen`, `vault init | check | pack | unpack | export`, plus `project`
- [`fixtures/`](fixtures) — conformance test vectors: the §9 reference vault
  in both physical forms, plus hostile containers (path traversal, symlinks,
  duplicate entries, a decompression bomb) that a conforming reader MUST
  reject. See [`fixtures/README.md`](fixtures/README.md).

## The CLI

```sh
cargo install --git https://github.com/aaronbuilt/longitude-vault longitude-cli
```

Requires a recent stable [Rust toolchain](https://rustup.rs) to build; after
that the CLI is self-contained. It bundles age and generates keys itself
(`longitude keygen`), so the whole create → encrypt → project loop needs
nothing else installed. Stock [age](https://age-encryption.org) is **optional**
— you only need it for the `age -d | zstd -d | tar -x` recovery one-liner that
opens a vault with zero Longitude software.

### Create and validate

`init --demo` writes the complete SPEC §9 example vault — a person with a
brokerage account, cold-storage BTC, a mortgage, two months of snapshots,
and two life-design scenarios — so every command below works out of the box:

```console
$ longitude vault init my.lonvault --demo
created my.lonvault (10 documents)

next steps:
  longitude keygen -o identity.txt     # make a device key (keep it safe)
  longitude vault pack my.lonvault -o vault.lon -i identity.txt

$ longitude vault check my.lonvault
vault is valid — no errors, no warnings
```

`check` is the SPEC §8 validator. Errors are spec violations; warnings are
things a human should look at (residency months that don't sum to 12, a
liability secured by an account that doesn't exist). It works on encrypted
`.lon` files too.

### Encrypt, decrypt, export

Keys are ordinary age keys — `longitude keygen` writes one, and `age-keygen`
writes a byte-compatible file if you'd rather use stock age. There is nothing
Longitude-specific to lose:

```console
$ longitude keygen -o identity.txt
Public key: age1rp8qlffdvad3wzx9y3jxmkdcwvqdp3e25a6p035cr8r4y8xxsapqtyus69
wrote identity to identity.txt — back it up; it is the only way to open vaults encrypted to it (§6.1)

$ longitude vault pack my.lonvault -o vault.lon -i identity.txt
vault is valid — no errors, no warnings
note: only one recipient. The spec strongly recommends encrypting to your device keys plus an offline recovery key (§6.1).
packed 10 documents → vault.lon

$ longitude vault unpack vault.lon -o restored -i identity.txt
unpacked 10 documents → restored
vault is valid — no errors, no warnings
```

`pack` refuses to encrypt an invalid vault, encrypts to every key you pass
(device keys plus an offline recovery key is the recommended shape, §6.1),
and warns if you pass only one. `longitude vault export` writes the §6.4
passphrase-only form for handing a vault to someone without keys — after
telling you, loudly, that its security is then the passphrase alone.

### Project

`longitude project` runs the **open engine core**: a deterministic
single-scenario projection in real (inflation-adjusted) terms — investable
assets from your snapshots, demand-driven withdrawals (spending − income,
month by month), blended expected returns, FI date, depletion date, and the
Longitude Score:

```console
$ longitude project my.lonvault
Longitude — deterministic projection (open engine core)
All figures are real (today's prices), in USD. Estimates, not advice.

scenario         Half-life: Kraków + Tokyo (half-life-krakow-tokyo, targeted)
window           2027-01 → 2077-01 (50 years)

t₀ investable    331,596 USD  (snapshots as of 2026-06-30)
spending         63,600 USD / yr
real return      4.6% / yr (blended)
SWR              4.0%  →  FI number 1,590,000 USD
Longitude Score  20.9%  (investable ÷ FI number)

FI date          not reached within the horizon
depletion        2045-09  (a withdrawal could not be met)
end of horizon   0 USD

note: spending comes from profile.annual_spending — pricing residency blocks from cost-of-living data is outside the open projection
```

(Yes, the demo person's plan fails. Honest numbers are the product.) Add
`--table` for the year-by-year breakdown, `--scenario <id>` to pick a
scenario, and `-i identity.txt` to project straight off an encrypted
`.lon`. A liability's `secured_by` keeps a mortgage and its house out of
the investable math together; income streams grow in real terms on their
anniversaries; a depleted portfolio latches as failed but keeps simulating,
so a pension arriving later can still rescue the path.

With `--simple` the scenario's `[withdrawal]` strategy drives spending
instead (the ficalc-style paradigm — a portfolio plus a rule, no plan).
The v0.1 registry is `constant-dollar`, `fixed-percentage`,
`percent-with-bounds` (with optional `floor`/`ceiling` clamps), `vpw`, and
`discretionary-guardrail` — the two-bucket flexibility rule (after
[Madfientist × Nick Maggiulli](https://www.madfientist.com/discretionary-withdrawal-strategy/)):
your essential spending behaves as constant-dollar, and the discretionary
remainder gets cut when the market is 10%/20% off its highs. The split is
required (`essential` as Money, or `essential_fraction`) — the engine
refuses to guess it. This deterministic pass has no market path, so it
funds the discretionary budget at its historical expected-value share
(S&P monthly closes, 1926–2022) and says so in a note; the market-state
path simulation belongs to the product engine.

```console
$ longitude project my.lonvault --simple --scenario stay-home
…
t₀ investable    331,596 USD  (snapshots as of 2026-06-30)
spending         strategy-driven: constant-dollar @ 4.0%
  first year     13,264 USD / yr
  across years   13,264 USD – 13,264 USD / yr
real return      0.0% / yr (blended)
Longitude Score  (a plan concept — not computed in simple mode)

FI date          not reached within the horizon
depletion        2051-06  (a withdrawal could not be met)
end of horizon   0 USD

note: no [[portfolio.allocation]] with weight + expected_return — assuming a 0% real return
```

The 4% rule at a 0% real return depletes in exactly 25 years — the
closed-form results are pinned by tests, which is what makes this CLI the
reference for cross-validating the product engine.

Deliberately out of scope here: Monte Carlo, cost-of-living data, tax, and
visa modeling — that's the product's engine, built on this core. Estimates,
not advice.

### The liberation guarantee, tested

CI includes a job that opens the conformance vault with **stock `age`,
`zstd`, and `tar` only** and diffs it against the plaintext form — the
data-liberation guarantee, continuously tested.

## Status

Spec: **v0.1 rev 7** (2026-07-14) — published and implemented, stable core,
reserved extensions marked in the spec. Reference implementation:
**v0.1.0** — validation, both physical forms, §5.4 hardening, conformance
fixtures, and the open engine core (deterministic projection plus the
five-strategy withdrawal registry). The format is young and feedback is welcome — open an issue for
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
