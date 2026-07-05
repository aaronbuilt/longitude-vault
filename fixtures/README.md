# Conformance fixtures

Test vectors for implementations of the vault format. The reference
implementation's conformance suite
(`crates/longitude-vault/tests/conformance.rs`) runs against these; any other
implementation should pass the equivalents.

Regenerate with `cargo run -p fixture-gen` (the identity is reused if
present; container bytes change on every run because age encryption is
randomized).

## Key material

| File | What |
|---|---|
| `identities/fixture-key.txt` | **TEST KEY, publicly committed.** X25519 identity every encrypted fixture is addressed to. Never use it for real data. |
| `identities/fixture-key.pub` | Its public key (the fixture recipient). |

`valid/demo-export.lon` uses the passphrase `longitude-fixture-passphrase`.

## `valid/` — MUST be accepted

| Fixture | What it exercises |
|---|---|
| `demo.lonvault/` | The complete SPEC §9 reference vault in plaintext mode (§5.1). Validates with zero errors and zero warnings. |
| `demo.lon` | The same vault in container mode (§5.2), encrypted to the fixture key. Logical content must equal `demo.lonvault/`. Also liberatable with stock tools: `age -d -i identities/fixture-key.txt valid/demo.lon \| zstd -d \| tar -x`. |
| `demo-export.lon` | The same vault as a passphrase-only export (§6.4): single scrypt stanza. Readers MUST accept it and SHOULD surface the export-mode warning (§8). |

## `hostile/` — MUST be rejected (§5.4)

Each violates exactly one reading rule. All decrypt successfully with the
fixture key — the *container* layer is what must refuse them.

| Fixture | Violation |
|---|---|
| `traversal.lon` | Entry path contains a `..` segment (`../escape.toml`). |
| `absolute.lon` | Absolute entry path (`/tmp/evil.toml`). |
| `symlink.lon` | Symlink entry (→ `/etc/passwd`). |
| `hardlink.lon` | Hardlink entry. |
| `duplicate.lon` | Two entries with the same path (`manifest.toml` twice). |
| `badname.lon` | Filename violating the §3.2 grammar inside a §2 directory (`accounts/Bad Name.toml`). |
| `bomb.lon` | Decompression bomb: a ~2 KiB container holding a 64 MiB document. Rejected by the per-document limit and/or the streaming decompressed-size ceiling. |
