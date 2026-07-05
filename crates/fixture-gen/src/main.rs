//! Generates the conformance fixtures under `fixtures/`.
//!
//! Valid fixtures go through the library's writer (so they are also a check
//! on it). Hostile fixtures are built from raw, hand-rolled tar headers so
//! nothing in the toolchain can refuse to produce them — each one violates a
//! specific SPEC §5.4 rule and a conforming reader MUST reject it.
//!
//! Idempotent on the identity: if `fixtures/identities/fixture-key.txt`
//! exists it is reused; container bytes still change on every run because
//! age encryption is randomized. Run once and commit.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result};
use longitude_vault::{demo, pack};

/// Fixed so the plaintext fixture vault is byte-stable across runs.
const FIXTURE_VAULT_ID: &str = "6f2a1b3c-4d5e-4f60-8a7b-9c0d1e2f3a4b";
const FIXTURE_CREATED: &str = "2026-07-04T12:00:00Z";
/// Documented in fixtures/README.md; used by demo-export.lon.
const FIXTURE_PASSPHRASE: &str = "longitude-fixture-passphrase";

fn main() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    fs::create_dir_all(root.join("identities"))?;
    fs::create_dir_all(root.join("valid"))?;
    fs::create_dir_all(root.join("hostile"))?;

    // ---- fixture identity --------------------------------------------------
    let key_path = root.join("identities/fixture-key.txt");
    let identity = if key_path.exists() {
        let contents = fs::read_to_string(&key_path)?;
        let line = contents
            .lines()
            .find(|l| l.starts_with("AGE-SECRET-KEY-"))
            .context("fixture-key.txt has no AGE-SECRET-KEY line")?;
        age::x25519::Identity::from_str(line)
            .map_err(|e| anyhow::anyhow!("parsing fixture key: {e}"))?
    } else {
        let identity = age::x25519::Identity::generate();
        let mut f = fs::File::create(&key_path)?;
        writeln!(
            f,
            "# TEST KEY — publicly committed conformance fixture key."
        )?;
        writeln!(f, "# NEVER use it to encrypt real data.")?;
        writeln!(f, "# public key: {}", identity.to_public())?;
        writeln!(f, "{}", expose(&identity))?;
        identity
    };
    let recipient = identity.to_public();
    fs::write(
        root.join("identities/fixture-key.pub"),
        format!("{recipient}\n"),
    )?;

    // ---- valid fixtures ----------------------------------------------------
    let vault = demo::demo_vault(FIXTURE_VAULT_ID, FIXTURE_CREATED);

    let demo_dir = root.join("valid/demo.lonvault");
    if demo_dir.exists() {
        fs::remove_dir_all(&demo_dir)?;
    }
    longitude_vault::container::write_dir(&vault, &demo_dir)?;

    let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(recipient.clone())];
    pack(&vault, &recipients, &root.join("valid/demo.lon"))?;

    let scrypt: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(age::scrypt::Recipient::new(
        FIXTURE_PASSPHRASE.to_string().into(),
    ))];
    pack(&vault, &scrypt, &root.join("valid/demo-export.lon"))?;

    // ---- hostile fixtures ----------------------------------------------------
    let manifest = vault.get("manifest.toml").unwrap().bytes.clone();

    // §5.4: `..` path segments are forbidden.
    write_hostile(
        &root.join("hostile/traversal.lon"),
        &[raw_entry("../escape.toml", b'0', b"boom = true\n", "")],
        &recipient,
    )?;
    // §5.4: absolute entry paths are forbidden.
    write_hostile(
        &root.join("hostile/absolute.lon"),
        &[raw_entry("/tmp/evil.toml", b'0', b"boom = true\n", "")],
        &recipient,
    )?;
    // §5.4: no symlinks.
    write_hostile(
        &root.join("hostile/symlink.lon"),
        &[raw_entry("notes/link.md", b'2', b"", "/etc/passwd")],
        &recipient,
    )?;
    // §5.4: no hardlinks.
    write_hostile(
        &root.join("hostile/hardlink.lon"),
        &[
            raw_entry("manifest.toml", b'0', &manifest, ""),
            raw_entry("notes/link.md", b'1', b"", "manifest.toml"),
        ],
        &recipient,
    )?;
    // §5.4: no duplicate entry paths.
    write_hostile(
        &root.join("hostile/duplicate.lon"),
        &[
            raw_entry("manifest.toml", b'0', &manifest, ""),
            raw_entry("manifest.toml", b'0', &manifest, ""),
        ],
        &recipient,
    )?;
    // §5.4: filename grammar within the §2 directories.
    write_hostile(
        &root.join("hostile/badname.lon"),
        &[raw_entry(
            "accounts/Bad Name.toml",
            b'0',
            b"id = \"x\"\n",
            "",
        )],
        &recipient,
    )?;
    // §5.4 resource limits: a 64 MiB document (also trips a modest streaming
    // ceiling — compressed, this whole container is a few KiB).
    let huge = vec![0u8; 64 * 1024 * 1024];
    write_hostile(
        &root.join("hostile/bomb.lon"),
        &[raw_entry("notes/huge.md", b'0', &huge, "")],
        &recipient,
    )?;

    println!("fixtures written to {}", root.canonicalize()?.display());
    Ok(())
}

fn expose(identity: &age::x25519::Identity) -> String {
    use age::secrecy::ExposeSecret;
    identity.to_string().expose_secret().to_string()
}

/// One raw ustar entry: 512-byte header + data padded to 512.
fn raw_entry(name: &str, typeflag: u8, data: &[u8], linkname: &str) -> Vec<u8> {
    let mut header = [0u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    let size = format!("{:011o}\0", data.len());
    header[124..136].copy_from_slice(size.as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].copy_from_slice(b"        "); // checksum: spaces while summing
    header[156] = typeflag;
    header[157..157 + linkname.len()].copy_from_slice(linkname.as_bytes());
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u32 = header.iter().map(|&b| b as u32).sum();
    let checksum = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(checksum.as_bytes());

    let mut out = header.to_vec();
    out.extend_from_slice(data);
    let pad = (512 - data.len() % 512) % 512;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

/// tar(entries) + end-of-archive marker, zstd, age → .lon
fn write_hostile(
    out: &Path,
    entries: &[Vec<u8>],
    recipient: &age::x25519::Recipient,
) -> Result<()> {
    let mut archive = Vec::new();
    for e in entries {
        archive.extend_from_slice(e);
    }
    archive.extend(std::iter::repeat_n(0u8, 1024)); // two zero blocks

    let compressed = zstd::stream::encode_all(archive.as_slice(), 9)?;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient as _))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut writer = encryptor
        .wrap_output(fs::File::create(out)?)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    writer.write_all(&compressed)?;
    writer.finish().map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}
