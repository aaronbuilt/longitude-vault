# The Longitude Vault Format — Specification v0.1 (draft)

*Status: draft, rev 5 · 2026-07-05 — rev 5 documents the optional
`floor`/`ceiling` Money fields on `[withdrawal]` (§4.5), the annual clamp
used by the `percent-with-bounds` withdrawal strategy. Rev 4 (2026-07-04)
was the security-hardening and publication pass: untrusted-vault reading
rules (§5.4), an explicit statement of what age does and does not provide
(§6.5), key rotation (§6.6), a self-contained threat model (§7), and removal
of references to internal Longitude documents.*
*This is the open, published specification of the Longitude vault format. The
reference CLI implements it.*

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be
interpreted as described in RFC 2119.

---

## 1. Overview

A **vault** is the complete, self-contained record of a user's financial life in
Longitude: profile, accounts, holdings, balance history, life-design scenarios
(Meridians), and the user's overrides of world-data assumptions.

Design goals, in priority order:

1. **User-owned.** The vault is an ordinary file (or folder) on the user's disk. No
   server is required to read, write, or understand it.
2. **Liberatable with standard tools.** The encrypted container is a standard
   [`age`](https://age-encryption.org/v1) file wrapping a zstd-compressed tar archive.
   `age -d -i identity.txt vault.lon | zstd -d | tar -x` recovers everything with
   zero Longitude software (passphrase-protected identities add one more stock
   `age -d`; see §5.2). This property is normative, not incidental.
3. **Human-readable and diffable.** Documents are TOML: readable in any editor,
   line-diffable under git in plaintext mode.
4. **Forward-compatible.** Unknown fields survive round-trips; versioning is explicit.
5. **Free of secrets and licensed data.** Never credentials or private keys; never
   embedded third-party datasets (only *references* to world-data keys, plus the
   user's own override values).

Non-goals: transactional/ledger accounting (see beancount et al.), multi-user
vaults, storage of API keys or credentials of any kind.

### 1.1 Notable design decisions

- Holdings are inline `[[holding]]` tables within their account file, not a
  separate directory: an account file is the complete picture of that account.
- Passphrase KDF is **scrypt** as defined by age's scrypt recipient stanza (an
  earlier draft specified Argon2id). Adopting the standard age format unmodified
  buys universal tooling interop, which outweighs the KDF preference; see §6.3.
- age forbids mixing an scrypt stanza with other recipients, so an earlier
  "passphrase as one recipient among peers" sketch was unimplementable. The
  vault file is encrypted to **X25519 recipients only**; passphrase protection
  wraps the *identity file*, not the vault. See §6.1.

---

## 2. Logical model

A vault is a set of **documents** — TOML files, plus optional markdown notes —
organized as:

```
<vault-root>/
  manifest.toml          # REQUIRED — identity, versioning, base currency
  profile.toml           # REQUIRED — the user: passports, ages, assumptions
  accounts/<id>.toml     # 0..n — one file per account, holdings inline
  snapshots/<date>.toml  # 0..n — dated balance snapshots (net-worth history)
  scenarios/<id>.toml    # 0..n — Meridians (life designs)
  overrides/<name>.toml  # 0..n — user overrides of world-data values
  transactions/<name>.toml  # 0..n, OPTIONAL — cashflow entries (schema deferred, §4.7)
  notes/<name>.md        # 0..n, OPTIONAL — free-form user notes (markdown)
```

Referential graph: snapshots reference accounts by id; scenarios reference the
profile implicitly and world-data keys explicitly; overrides reference world-data
keys. There are no other cross-references in v0.1.

---

## 3. Common conventions

### 3.1 Encoding & syntax
- Documents MUST be valid **TOML v1.0**, UTF-8, no BOM. Writers SHOULD use LF line
  endings; readers MUST accept CRLF.
- Key names are `snake_case`. Table and array-of-table names are singular
  (`[[holding]]`, `[[balance]]`, `[[residency]]`).

### 3.2 Identifiers
- Entity ids (`id` fields, account/scenario filenames) MUST match
  `[a-z0-9][a-z0-9-]{0,63}` (lowercase kebab slugs).
- Ids MUST be unique within their entity type and SHOULD be treated as immutable
  once created (they are referenced by other documents and by external tooling).
- Filenames MUST equal the contained `id` (accounts, scenarios) or the snapshot
  `date` (snapshots): `accounts/schwab-brokerage.toml` ⇔ `id = "schwab-brokerage"`.
- `vault_id` in the manifest is a UUIDv4 string, generated at vault creation, never
  changed. Used by Chronometer to distinguish vaults; carries no meaning otherwise.

### 3.3 Dates & times
- Calendar dates use TOML native date type (`2026-06-30`), interpreted as civil
  dates with no timezone.
- Timestamps (rare; e.g. `created`) use TOML offset date-time (RFC 3339).

### 3.4 Money (normative — the most important convention)
- Monetary amounts MUST be **decimal strings**, never TOML floats or integers:
  `{ amount = "412345.67", currency = "USD" }` (an inline table, the **Money**
  type). Implementations MUST parse into exact decimal types and MUST NOT round-trip
  through binary floating point.
- **Decimal-string grammar (normative):** every decimal string in this format —
  amounts, quantities, rates, override values — MUST match
  `-?(0|[1-9][0-9]*)(\.[0-9]+)?`. No leading `+`, no exponents, no thousands
  separators, no leading zeros, no bare `.5`, no trailing `.`.
- `currency` is an ISO 4217 alphabetic code, or an asset code for crypto (`BTC`,
  `ETH`); asset codes MUST NOT collide with ISO 4217.
- Negative amounts use a leading `-`. Liabilities are represented as accounts of
  `type = "liability"` with positive balances denoting amounts owed (see §4.3).
- Quantities (share counts, coin amounts) are likewise decimal strings.

### 3.5 Rates & percentages
- All rates (SWR, expected returns, volatility, inflation, growth) are **decimal
  fractions as strings**: 4% ⇒ `"0.040"`. There is deliberately no percent-unit
  field anywhere in the format.

### 3.6 Places & world-data keys
- A **place** is `"<country>"` or `"<country>/<city>"`, where country is ISO 3166-1
  alpha-2 lowercase and city is a kebab slug from the Longitude place registry
  (published with the data bundles): `"pl/krakow"`, `"jp/tokyo"`, `"us/detroit"`, `"ge"`.
- A **world-data key** is a dot path:
  `<domain>.<country>[.<city>].<category>[.<subkey>]` — e.g.
  `col.pl.krakow.housing.comfortable`, `tax.us.federal.ltcg`, `visa.jp.us-passport.max-stay-days`.
  Domains in v0.1: `col`, `tax`, `visa`, `fx`, `climate`, `safety`, `livability`.
  The key registry itself is versioned with the data bundles, not this spec.
- **Case convention (normative):** everything place-shaped — place strings,
  world-data keys, `tax_residency`, `tax_jurisdiction` — is lowercase. `passports`
  and `currency` are uppercase, because they are ISO *codes used as codes*
  (ISO 3166-1 / ISO 4217), not places. This asymmetry is deliberate.

### 3.7 Extensibility & compatibility (normative)
- Readers MUST ignore — and writers MUST preserve on round-trip — any key or table
  they do not recognize. (This is the forward-compatibility backbone.)
- Third-party tools writing custom fields MUST prefix them `x_` (keys) or `x-`
  (table names): `x_myscript_tag = "..."`. Longitude will never define `x_` keys.
- Implementations SHOULD preserve comments and formatting when editing documents
  (e.g. via a format-preserving TOML library); they MUST NOT reorder or reformat
  documents they did not modify.
- `schema` in the manifest is `MAJOR.MINOR`. Readers MUST refuse a higher MAJOR,
  and MUST accept (per the unknown-key rule) any MINOR within a known MAJOR.

---

## 4. Document schemas

Fields marked ◆ are required; everything else optional.

### 4.1 `manifest.toml`
```toml
format = "longitude-vault"        # ◆ literal; the folder-mode detection marker
schema = "0.1"                    # ◆ format version, MAJOR.MINOR
vault_id = "1c9f0f8e-…"           # ◆ UUIDv4, immutable
base_currency = "USD"             # ◆ valuation currency for aggregates
created = 2026-07-03T09:00:00Z
modified = 2026-07-03T09:00:00Z   # updated on every write; the vault's human-visible
                                  # timestamp (lives inside the ciphertext — no leak)
generator = "longitude-cli 0.1.0" # last writer, informational
```

### 4.2 `profile.toml`
The user, and the assumptions used as defaults platform-wide.
```toml
birth_year = 1990                   # year only — no birthdate precision needed
passports = ["US"]                  # ◆ required key, MAY be an empty array (visa/tax
                                    #   features degrade — §8 warning); ISO 3166-1
                                    #   alpha-2, uppercase; drives visa/tax
tax_residency = "us"                # current tax home (place string)
target_retirement_age = 45
annual_spending = { amount = "60000", currency = "USD" }
annual_savings  = { amount = "40000", currency = "USD" }
swr = "0.040"
lifestyle = "comfortable"           # lean | comfortable | luxury (default tier)
display_currency = "USD"            # view preference; ≠ base_currency semantics
household = 1                       # people covered by this vault's spending
```

### 4.3 `accounts/<id>.toml`
```toml
id = "schwab-brokerage"             # ◆ = filename
name = "Schwab Brokerage"           # ◆ display name
type = "brokerage"                  # ◆ cash | brokerage | retirement | crypto |
                                    #   real-estate | liability | other
currency = "USD"                    # ◆ account's native currency
tax_jurisdiction = "us"             # place string (§3.6), lowercase
tax_wrapper = "taxable"             # taxable | traditional | roth | pension | isa | other
institution = "Charles Schwab"      # free text; NEVER credentials
opened = 2015-03-01
# closed = 2031-06-30               # optional; presence = closed as of this date.
                                    # Aggregation treats the account as zero from
                                    # this date (overrides snapshot carry-forward).
notes = ""

[[holding]]                         # 0..n — positions held in this account
asset = "VT"                        # ◆ ticker/ISIN/asset code/custom slug
kind = "security"                   # ◆ security | crypto | cash | custom
quantity = "1234.567"               # ◆ decimal string
cost_basis = { amount = "95000.00", currency = "USD" }
acquired = 2019-05-10

# Crypto, watch-only (never private keys — normative, §7):
# [[holding]]
# asset = "BTC"
# kind = "crypto"
# quantity = "1.50000000"                       # manual amount…
# source = { descriptor = "wpkh([9a1b2c3d/84h/0h/0h]xpub6C…/0/*)" }
#                                               # …or output descriptor / xpub for
#                                               # watch-only balance derivation.
#                                               # If both, `source` wins at refresh
#                                               # and `quantity` is the cached value.
```
Liability accounts (`type = "liability"`): balances denote amount owed (positive);
aggregation subtracts them. `[[holding]]` is not used on liabilities. A liability
MAY carry `secured_by = "<account-id>"` naming the account it is secured against
(a mortgage names its house): the engine then keeps the pair together — both in
net worth, and a liability secured by a non-investable asset stays out of
investable-asset math. Absent `secured_by`, a liability is treated as unsecured.

There is deliberately no `property` holding kind: real estate is an account
(`type = "real-estate"`) whose value lives in snapshots, like any other
non-quantity asset. Holdings exist only for things with a quantity × price.

### 4.4 `snapshots/<date>.toml`
The net-worth history spine. One file per snapshot moment; monthly is the expected
rhythm but any cadence is valid — the filename is the date.
```toml
date = 2026-06-30                   # ◆ = filename (YYYY-MM-DD.toml)
note = "mid-year check"

[[balance]]                         # 1..n
account = "schwab-brokerage"        # ◆ account id
value = { amount = "412345.67", currency = "USD" }   # ◆

[[balance]]
account = "mortgage"
value = { amount = "182000.00", currency = "USD" }   # liability: amount owed
```
**Valuation semantics (normative):** a `balance.value` is the
**total observed value of the account as of the snapshot date, inclusive of its
holdings**. Implementations MUST NOT add holdings-derived value on top of a snapshot
balance. For *current* value, implementations SHOULD price holdings live where
quotes are available and fall back to the latest snapshot; the exact current-value
policy is engine-spec territory, but the inclusive meaning of a snapshot balance is
format-level and fixed here.

A snapshot need not cover every account; readers MUST treat missing accounts as
"no observation" (carry forward the latest prior balance), not zero — except
accounts past their `closed` date, which are zero regardless (§4.3). A balance
entry dated after its account's `closed` date is a §8 warning.

### 4.5 `scenarios/<id>.toml` — a Meridian
The format defines the **shape**; computation semantics are engine territory,
documented with the engine, not the format. Unknown engine parameters flow
through per §3.7.
```toml
id = "half-life-krakow-tokyo"       # ◆
name = "Half-life: Kraków + Tokyo"  # ◆
targeted = true                     # the Meridian the Longitude Score tracks;
                                    # at most one scenario MAY set this true
created = 2026-07-03

[timeline]
start = 2027-01-01                  # optional; omitted = engine's "now"
horizon_years = 50

# Residency: full-expat is one block with months_per_year = 12.
# A block has EITHER months_per_year (recurring annual pattern) XOR from/to
# (explicit one-off date range) — never both. Recurring blocks SHOULD sum to
# 12 months/year (≠ 12 is a §8 warning, since partial designs may be deliberate).
[[residency]]
place = "pl/krakow"                 # ◆ place string (§3.6)
months_per_year = 5
# One-off form:
# [[residency]]
# place = "th/chiang-mai"
# from = 2028-11-01                 # ◆ (this form)
# to = 2029-02-28                   # ◆ (this form) inclusive civil dates
[[residency]]
place = "jp/tokyo"
months_per_year = 4
[[residency]]
place = "us/detroit"
months_per_year = 3

[expenses]
lifestyle = "comfortable"           # lean | comfortable | luxury;
                                    # engine prices residency blocks from CoL data
                                    # at this tier, honoring overrides/ (§4.6)
extra_monthly = { amount = "300", currency = "USD" }   # flat add-on (subscriptions…)

[[income]]
id = "salary"
kind = "employment"                 # employment | self-employment | pension |
                                    #   social-security | rental | one-off | other
amount = { amount = "8500.00", currency = "USD" }
frequency = "monthly"               # monthly | annual | once
from = 2027-01-01
to = 2031-12-31
growth = "0.020"

[portfolio]
from_vault = true                   # start from current vault holdings
[[portfolio.allocation]]
class = "equities-global"           # asset-class slug (engine registry)
weight = "0.70"                     # target weight; weights SHOULD sum to 1
expected_return = "0.050"           # real, annualized
volatility = "0.160"
[[portfolio.allocation]]
class = "btc"
weight = "0.10"
expected_return = "0.080"
volatility = "0.600"

[withdrawal]
strategy = "fixed-percentage"       # engine strategy registry; drives spending in
                                    # simple mode / the FIRE-calc wedge only —
                                    # Meridian simulation is demand-driven
rate = "0.040"                      # doubles as this scenario's SWR for the
                                    # FI number / Longitude Score
# percent-with-bounds only — annual clamp on strategy spending, real terms:
# floor   = { amount = "30000", currency = "USD" }   # Money, optional
# ceiling = { amount = "80000", currency = "USD" }   # Money, optional

[tax]
# Citizenship-driven flags default from profile.passports; scenario may override.
feie = true
treaty_positions = ["us-pl"]

[fx]
# Optional per-pair drift overrides; default engine behavior otherwise.
# usd_pln_drift = "0.000"
```

### 4.6 `overrides/<name>.toml`
User corrections to world-data values (their rent, their insurance quote). Filename
is a user-chosen slug (§3.2 grammar); grouping is free-form.
```toml
[[override]]
key = "col.pl.krakow.housing.comfortable"   # ◆ world-data key (§3.6)
value = "4200"                              # ◆ decimal string
currency = "PLN"                            # for monetary keys
note = "actual rent, 2-room Kazimierz, 2026"
as_of = 2026-06-01
```
Readers MUST apply overrides in place of bundle values wherever the key is used.
Two overrides of the same key across files: last-in-lexical-filename-order wins;
within one file, last in document order wins; writers SHOULD warn in both cases.
In v0.1, overrides are valid **only for numeric world-data keys** (`value` is a
decimal string per §3.4); overriding boolean/enum keys (e.g. visa flags) is
deferred to a future MINOR.

### 4.7 `transactions/` and `notes/` (optional, v0.1-reserved)
Transactions (cashflow entries) and notes are named and reserved but their schemas
are deliberately deferred; files present under these directories flow through under
the unknown-content rule. Not required for any v0.1 feature.

---

## 5. On-disk representations

A vault has exactly two interchangeable physical forms. Implementations MUST
support both and MUST produce identical logical content from either.

### 5.1 Plaintext mode — a directory
Any directory whose root contains a `manifest.toml` with `format = "longitude-vault"`.
Suggested (not required) directory name suffix: `*.lonvault/`. The user brings
their own protection (git-crypt, encrypted disk, age of the whole folder, etc.).
For power users; preserves git line-diffs.

Dotfiles and dot-directories (`.git/`, `.DS_Store`, editor droppings) are not part
of the vault; container-mode writers (§5.2) MUST NOT pack them. **All other
unrecognized top-level entries MUST be preserved byte-for-byte on pack/unpack**
(writers SHOULD warn) — this is the directory-level extension of §3.7's unknown-key
rule, and it is what keeps an older MINOR app from silently destroying a newer
vault's directories.

### 5.2 Encrypted container mode — the `.lon` file (default)
A single file, extension `.lon`, constructed as:

```
vault.lon = age( zstd( tar( <vault-root contents> ) ) )
```

Layer by layer, outermost first:

1. **Encryption — standard age v1** (file begins with the ASCII header
   `age-encryption.org/v1`). Recipients per §6. Because this layer is stock age,
   any age implementation can decrypt it.
2. **Compression — zstd**, single frame, any standard level (writers SHOULD use a
   mid level, e.g. 9–12).
3. **Archive — POSIX pax tar.** Entries are the vault documents with paths
   relative to the vault root (`manifest.toml`, `accounts/schwab-brokerage.toml`, …),
   no leading `./` or wrapper directory. Writers MUST emit entries in sorted path
   order with normalized metadata (uid/gid 0, mode 0644 files / 0755 directories,
   **mtime = 0 on every entry**) so that identical logical content yields identical
   archives. (Reproducibility applies to the *archive*, pre-encryption: age output
   is randomized, so ciphertexts never repeat. Change detection and dedup therefore
   happen client-side, before encryption — by design; ciphertext-equality dedup
   would require convergent encryption, which leaks equality to the server.)
   The vault's human-visible timestamp is `modified` in the manifest (§4.1), inside
   the ciphertext — never in archive metadata.

**Data-liberation guarantee (normative):** a `.lon` file MUST be fully recoverable
with stock tooling and nothing else:

```sh
# Standard vault (X25519 recipients — §6.1):
age -d -i identity.txt vault.lon | zstd -d | tar -x

# Passphrase-protected identity (§6.1): one extra stock step
age -d identity.txt.age > identity.txt   # prompts for the passphrase
age -d -i identity.txt vault.lon | zstd -d | tar -x

# Passphrase-only export vault (§6.4):
age -d vault.lon | zstd -d | tar -x      # prompts for the passphrase
```

(The two-step identity recovery writes a plaintext key to disk; where the shell
allows it, prefer process substitution — `age -d -i <(age -d identity.txt.age)
vault.lon | zstd -d | tar -x` — or delete `identity.txt` when done.)

No Longitude-specific framing, headers, or trailers may be added at any layer.

**Atomicity:** writers MUST write to a temporary file in the same directory and
rename over the target. Writers SHOULD maintain rotating local backups
(`vault.lon.bak.1…3`) — implementation guidance, not format.

### 5.3 Mode conversion
Pack/unpack between modes is lossless by construction. `longitude vault pack` /
`unpack` in the reference CLI. Comments and formatting inside TOML documents are
bytes like any others — both modes preserve them identically.

### 5.4 Reading untrusted vaults (normative)

A vault received from outside the user's own machines — a shared export, a
demo, an attachment — is untrusted input. Readers MUST treat every container
they unpack as potentially hostile:

- **Archive entries.** Readers MUST reject a container whose archive contains:
  an absolute entry path; any path segment equal to `..`; an entry type other
  than regular file or directory (no symlinks, hardlinks, device nodes, or
  FIFOs); or two entries with the same path. Entry paths MUST be resolved
  strictly relative to the extraction root.
- **Filename grammar.** Within the §2 directories, filenames MUST match the
  §3.2 slug grammar plus extension (`[a-z0-9][a-z0-9-]{0,63}\.toml`, `.md` under
  `notes/`), the snapshot date form `YYYY-MM-DD.toml`, or the fixed names
  `manifest.toml` / `profile.toml`. Entries under unrecognized top-level
  directories flow through per §5.1 but remain subject to the entry rules
  above. (The restricted grammar also prevents case-collision and
  Unicode-normalization aliasing on case-insensitive filesystems.)
- **Resource limits.** A tiny `.lon` can decompress to an arbitrarily large
  payload. Readers MUST enforce a ceiling on total decompressed size, checked
  incrementally while streaming (a default cap with an explicit user override
  is conforming), and SHOULD bound entry count and per-document size before
  parsing TOML.
- **Display hardening.** Free-text fields (`name`, `note`, `institution`, …)
  may legally contain any Unicode, including control characters. Tooling MUST
  strip or escape control characters before writing such values to a terminal
  or log (terminal escape injection).

---

## 6. Keys & encryption

### 6.1 Recipient model (age-native)

age's spec forbids mixing its scrypt (passphrase) stanza with any other recipient
stanza — *"an scrypt stanza, if present, MUST be the only stanza in the header"* —
so a passphrase can never be "one recipient among peers" on the vault itself. The
model is therefore layered (Bitwarden-shaped):

- **The vault file is encrypted to X25519 recipients only.** Standard vaults MUST
  NOT carry an scrypt stanza (the sole exception is the export mode, §6.4).
- **Device keys** — age X25519 identities, one per device, stored in the OS
  keychain or a user-managed identity file. Multi-recipient encryption means *your
  desktop and your laptop can both open the vault without sharing secrets* — and
  Chronometer sync never touches key material.
- **Recovery key** — a printed/offline X25519 identity generated at vault creation
  (Bitwarden-style). STRONGLY RECOMMENDED default: every vault is encrypted to the
  user's device keys **plus** the recovery key.
- **Passphrase protection wraps the identity, not the vault:** an identity file MAY
  be stored passphrase-encrypted as a standard scrypt-only age file
  (`identity.txt.age`, exactly what `age -p` produces). The passphrase unlocks the
  key; the key unlocks the vault. Work factor: age's default (2^18) minimum;
  writers MAY increase.

Losing all identities (including the recovery key) = the data is unrecoverable.
That is the design (zero-knowledge); the hosted tier's opt-in escrow simply
holds an additional recipient identity server-side, and MUST be presented to
the user as exactly that.

### 6.2 What Chronometer sees — and could do
Sync uploads the `.lon` bytes (or, later, per-document encrypted CRDT updates —
out of scope for v0.1). The relay observes: ciphertext, size, timing, and the
age header's recipient stanza count/types. It can never observe document contents,
keys, or the vault structure. Because compression precedes encryption, ciphertext
*length* does track compressed content size: an observer watching sync over time
learns that the vault is growing and roughly how fast — nothing more.

A relay is also a storage adversary. It cannot forge a vault or read one
(§6.5), but it can withhold updates or serve an older, perfectly valid
ciphertext (rollback). Sync clients MUST keep a local high-water mark of the
manifest's `modified` timestamp — it lives inside the ciphertext, where a relay
cannot alter it — and MUST warn before accepting a vault whose `modified`
regresses.

### 6.3 KDF note
age's passphrase stanza uses **scrypt** (not Argon2id, contra the master-spec
draft). Rationale: adopting age unmodified buys universal tooling interop and a
heavily reviewed implementation; a custom Argon2id container would be strictly
worse for goal #2. If age ever ships an Argon2 stanza, a schema-MINOR bump adopts it.

### 6.4 Passphrase-only export mode
`longitude vault export --passphrase` MAY produce an **scrypt-only** `.lon`
(single scrypt stanza, per the age rule above). This is an *interchange* artifact —
hand a snapshot to a spouse, an executor, or your future self — not a daily-use
mode: **no recovery key can coexist with it**, and tooling MUST say so at creation.
Openable with nothing but `age -d` and the passphrase (§5.2). Readers MUST accept
scrypt-only vaults; writers MUST NOT save routine changes back to one (re-export
or convert to the standard recipient model instead).

An export's entire security rests on the passphrase against offline brute
force, and stock age's scrypt work factor is fixed — tooling SHOULD generate,
or strongly encourage, a high-entropy passphrase (six or more random words).

### 6.5 What age provides — and what it does not

age gives the container **confidentiality** and **ciphertext integrity**: a
tampered file fails to decrypt (authenticated header, and an authenticated
STREAM payload whose chunking also defeats truncation and reordering). Two
things it deliberately does not provide:

- **Sender authenticity.** age encrypts *to* recipients; it does not sign.
  Anyone who knows a recipient's public key can produce a valid vault encrypted
  to that recipient. Successful decryption proves the file was addressed to
  you — not that you, or any particular party, wrote it. This is why vaults
  from outside your own devices get the §5.4 treatment.
- **Freshness.** A valid ciphertext stays valid forever. Replay and rollback
  protection are protocol concerns, handled at the sync layer (§6.2), not by
  the file format.

### 6.6 Key rotation & revocation

Rotation is re-encryption: generate the new identity, write the vault to the
new recipient set (dropping the revoked key), refresh local backups. Two
consequences implementations MUST surface to the user:

- **Old ciphertexts remain decryptable by the revoked key.** Every blob synced,
  backed up, or exported before rotation is still openable with a stolen device
  key. After a suspected compromise, treat historical ciphertexts as exposed;
  rotation protects the vault *going forward*, not retroactively.
- Chronometer SHOULD delete superseded blobs on rotation, and local tooling
  SHOULD offer to overwrite rotating backups (`vault.lon.bak.1…3`) with the
  re-encrypted vault.

---

## 7. Security & privacy considerations

- **No secrets, ever (normative):** vault documents MUST NOT contain passwords,
  API keys, seed phrases, or private keys of any kind. `institution` is display
  text. Crypto holdings use watch-only descriptors/xpubs or manual quantities.
- **xpub privacy caveat:** an xpub/descriptor reveals *all* derived addresses
  (full balance + transaction history) to anyone who obtains it. Storing one in
  the vault is safe **because the vault is encrypted**; plaintext-mode users who
  git-push their vault MUST be warned by tooling when a `source` descriptor is
  present. Documents SHOULD prefer manual quantities in plaintext mode.
- **Balance refresh leaks:** deriving a watch-only balance requires querying chain
  data. Implementations SHOULD route such queries through the batched price proxy
  or the user's own node, and MUST NOT send descriptors to third-party APIs
  without explicit consent.
- **Threat model.** The format protects the vault **at rest** and **on
  untrusted storage** (sync relays, cloud drives, email attachments):
  confidentiality and integrity come from age (§6.5); substitution and
  rollback by a storage adversary are addressed at the sync layer (§6.2);
  hostile vault files are addressed by the reading rules (§5.4). Out of
  scope: a compromised endpoint — malware that can read process memory, the
  keychain, or the decrypted vault on the user's machine defeats any at-rest
  format — and traffic analysis beyond what §6.2 documents.

---

## 8. Validation

A conforming validator (in the reference CLI: `longitude vault check`) reports:
- **Errors** (vault invalid): TOML syntax; missing required fields; duplicate ids;
  filename ≠ id/date; unknown `schema` MAJOR; any non-string TOML type (float,
  integer, …) used for money/quantity/rate, or a string violating the §3.4 grammar;
  malformed Money/place/world-data-key syntax; >1 scenario with `targeted = true`;
  a residency block with both `months_per_year` and `from`/`to` (or neither);
  recurring residency blocks summing to more than 12 months/year;
  snapshot `balance.account` referencing a nonexistent account id;
  `secured_by` referencing a nonexistent account id, or present on a
  non-liability account; in container mode, any §5.4 violation (path
  traversal, forbidden entry types, duplicate paths, filename-grammar
  violations, resource-limit breach).
- **Warnings:** allocation weights not summing to ~1; recurring residency blocks
  summing ≠ 12 months/year; a snapshot balance dated after its account's `closed`
  date; overrides of the same key in multiple files (or twice in one file);
  descriptor present in a plaintext-mode vault; unrecognized top-level directories
  (preserved per §5.1); `passports` empty (visa/tax features degrade); vault is
  passphrase-only export mode (§6.4 — no recovery key possible).

---

## 9. Reference example (complete minimal vault)

```
demo.lonvault/
  manifest.toml      → format, schema = "0.1", vault_id, base_currency = "USD"
  profile.toml       → passports = ["US"], birth_year = 1990, swr = "0.040"
  accounts/
    schwab-brokerage.toml   → brokerage; [[holding]] VT 1234.567
    cold-storage.toml       → crypto; [[holding]] BTC 1.5 (manual quantity)
    mortgage.toml           → liability, currency USD
  snapshots/
    2026-05-31.toml  → balances for all three accounts
    2026-06-30.toml  → balances for all three accounts
  scenarios/
    half-life-krakow-tokyo.toml  → the §4.5 example, targeted = true
    stay-home.toml               → [[residency]] us/detroit 12mo baseline
  overrides/
    col-krakow.toml  → my actual Kraków rent
```
(The reference CLI will ship `longitude vault init --demo` generating exactly this.)

---

## 10. Open questions for v0.2

1. **Container framing for partial sync** — whole-blob `.lon` is v0.1; per-document
   encryption (CRDT-ready) will need an envelope format. Design constraint: keep
   the liberation guarantee (§5.2) for at-rest files regardless.
2. **Transactions schema** — deferred; decide whether to adopt a beancount-inspired
   posting model or a simpler single-entry cashflow log.
3. **Attachments** (statements, documents): probably a `files/` dir with
   content-addressed names; interacts with container size and sync.
4. **Place registry governance** — city slugs live in data bundles; spec needs a
   stability promise (slugs never reused/renamed once published).
5. **Multi-currency cost basis** — lots/tax-lot tracking is deliberately absent in
   v0.1; revisit when Tax Lab needs it.
6. **Asset identifier disambiguation** — `asset = "VT"` names a ticker but not an
   exchange; fine while price lookup is engine-side and user-confirmable, but an
   optional qualifier (MIC or ISIN) will be needed before the importer guesses.
7. **Boolean/enum overrides** — v0.1 restricts `overrides/` to numeric keys (§4.6);
   visa-flag-style overrides need a typed `value` story.
