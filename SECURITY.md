# Security

A vault holds an entire financial life, so security reports get priority
over everything else in this repo.

## Reporting

Email **hello@longitude.money** for anything sensitive — a way to make a
conforming reader misbehave on a hostile container, a hole in the threat
model, a weakness in the key model. Please don't open a public issue for
something exploitable before we've had a chance to fix it. You'll get a
reply from a human (there is exactly one of us) within a couple of days.

For non-sensitive spec feedback — ambiguities, missing MUSTs, hardening
ideas that don't expose anyone — public issues are welcome and appreciated.

## Scope

- `SPEC.md` — especially §5.4 (untrusted-container reading rules), §6.5
  (what age does and does not provide), and §7 (threat model)
- The reference implementation crates and the `longitude` CLI
- The conformance fixtures — including a hostile container the fixtures
  *should* contain but don't yet

Out of scope: the age encryption format itself (report to
[FiloSottile/age](https://github.com/FiloSottile/age)), and anything about
the longitude.money website or product — mail the same address, it just
isn't covered by this repo's spec.

## A note on the test key

`fixtures/identities/fixture-key.txt` is a real age private key committed
on purpose: the conformance vaults are encrypted to it so anyone can open
them. It protects nothing and never will. Finding it is not a
vulnerability — but nice grep.
