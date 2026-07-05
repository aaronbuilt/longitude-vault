//! `longitude` — reference CLI for the Longitude vault format.
//!
//! Everything here is stock-tool compatible by design (SPEC §5.2): a vault
//! this CLI writes can always be opened with `age -d … | zstd -d | tar -x`.

use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use longitude_vault::{
    pack, read_container, scan_header_stanzas, validate, Mode, RawVault, ReadLimits, Report,
    Severity,
};

#[derive(Parser)]
#[command(
    name = "longitude",
    version,
    about = "Reference CLI for the Longitude vault format (https://github.com/aaronbuilt/longitude-vault)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Work with vaults (the only namespace in v0.1)
    #[command(subcommand)]
    Vault(VaultCommand),
}

#[derive(Subcommand)]
enum VaultCommand {
    /// Create a new plaintext-mode vault directory
    Init {
        /// Directory to create
        dir: PathBuf,
        /// Generate the complete SPEC §9 demo vault instead of a minimal one
        #[arg(long)]
        demo: bool,
    },
    /// Validate a vault (directory or .lon container) per SPEC §8
    Check {
        /// Vault directory or .lon file
        path: PathBuf,
        /// age identity file (repeatable); may itself be passphrase-encrypted (.age)
        #[arg(short, long)]
        identity: Vec<PathBuf>,
        /// Decompressed-size ceiling in MiB (§5.4 resource limits)
        #[arg(long, default_value_t = 256)]
        max_size_mib: u64,
    },
    /// Encrypt a vault directory into a .lon container
    Pack {
        /// Vault directory (plaintext mode)
        dir: PathBuf,
        /// Output .lon path
        #[arg(short, long)]
        output: PathBuf,
        /// age X25519 recipient (age1…), repeatable
        #[arg(short, long)]
        recipient: Vec<String>,
        /// age identity file whose public key becomes a recipient (repeatable)
        #[arg(short, long)]
        identity: Vec<PathBuf>,
    },
    /// Decrypt a .lon container into a plaintext-mode directory
    Unpack {
        /// The .lon file
        file: PathBuf,
        /// Output directory (must not already exist)
        #[arg(short, long)]
        output: PathBuf,
        /// age identity file (repeatable); may itself be passphrase-encrypted (.age)
        #[arg(short, long)]
        identity: Vec<PathBuf>,
        /// Decompressed-size ceiling in MiB (§5.4 resource limits)
        #[arg(long, default_value_t = 256)]
        max_size_mib: u64,
    },
    /// Write a passphrase-only export: a .lon with a single scrypt stanza (§6.4)
    Export {
        /// Vault directory (plaintext mode)
        dir: PathBuf,
        /// Output .lon path
        #[arg(short, long)]
        output: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Vault(cmd) => match cmd {
            VaultCommand::Init { dir, demo } => cmd_init(&dir, demo),
            VaultCommand::Check {
                path,
                identity,
                max_size_mib,
            } => cmd_check(&path, &identity, max_size_mib),
            VaultCommand::Pack {
                dir,
                output,
                recipient,
                identity,
            } => cmd_pack(&dir, &output, &recipient, &identity),
            VaultCommand::Unpack {
                file,
                output,
                identity,
                max_size_mib,
            } => cmd_unpack(&file, &output, &identity, max_size_mib),
            VaultCommand::Export { dir, output } => cmd_export(&dir, &output),
        },
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

// ============================ commands ======================================

fn cmd_init(dir: &Path, demo: bool) -> Result<ExitCode> {
    if dir.exists() {
        bail!("{} already exists — refusing to overwrite", dir.display());
    }
    let vault_id = uuid::Uuid::new_v4().to_string();
    let now = humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string();
    let vault = if demo {
        longitude_vault::demo::demo_vault(&vault_id, &now)
    } else {
        longitude_vault::demo::minimal_vault(&vault_id, &now)
    };
    longitude_vault::container::write_dir(&vault, dir)?;
    println!(
        "created {} ({} document{})",
        dir.display(),
        vault.documents.len(),
        if vault.documents.len() == 1 { "" } else { "s" }
    );
    println!();
    println!("next steps:");
    println!("  age-keygen -o identity.txt          # make a device key (keep it safe)");
    println!(
        "  longitude vault pack {} -o vault.lon -i identity.txt",
        dir.display()
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_check(path: &Path, identity_paths: &[PathBuf], max_size_mib: u64) -> Result<ExitCode> {
    let (vault, mode) = load_vault(path, identity_paths, max_size_mib)?;
    let report = validate(&vault, mode);
    print_report(&report);
    Ok(if report.is_valid() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn cmd_pack(
    dir: &Path,
    output: &Path,
    recipient_strs: &[String],
    identity_paths: &[PathBuf],
) -> Result<ExitCode> {
    let vault = RawVault::load_dir(dir)
        .with_context(|| format!("reading vault directory {}", dir.display()))?;
    let report = validate(&vault, Mode::Plaintext);
    print_report(&report);
    if !report.is_valid() {
        bail!("refusing to pack an invalid vault (fix the errors above)");
    }

    let mut recipients: Vec<Box<dyn age::Recipient + Send>> = Vec::new();
    for s in recipient_strs {
        let r: age::x25519::Recipient = s
            .parse()
            .map_err(|e: &str| anyhow::anyhow!("bad recipient {s:?}: {e}"))?;
        recipients.push(Box::new(r));
    }
    for path in identity_paths {
        recipients.extend(
            parse_identity_file(path)?
                .to_recipients()
                .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?,
        );
    }
    if recipients.is_empty() {
        bail!("no recipients — pass -r <age1…> and/or -i <identity file> (§6.1)");
    }
    if recipients.len() == 1 {
        eprintln!(
            "note: only one recipient. The spec strongly recommends encrypting to your \
             device keys plus an offline recovery key (§6.1)."
        );
    }

    pack(&vault, &recipients, output)?;
    println!(
        "packed {} document{} → {}",
        vault.documents.len(),
        if vault.documents.len() == 1 { "" } else { "s" },
        output.display()
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_unpack(
    file: &Path,
    output: &Path,
    identity_paths: &[PathBuf],
    max_size_mib: u64,
) -> Result<ExitCode> {
    if output.exists() {
        bail!(
            "{} already exists — refusing to overwrite",
            output.display()
        );
    }
    let (vault, mode) = load_vault(file, identity_paths, max_size_mib)?;
    longitude_vault::container::write_dir(&vault, output)?;
    println!(
        "unpacked {} document{} → {}",
        vault.documents.len(),
        if vault.documents.len() == 1 { "" } else { "s" },
        output.display()
    );
    let report = validate(&vault, mode);
    print_report(&report);
    Ok(ExitCode::SUCCESS)
}

fn cmd_export(dir: &Path, output: &Path) -> Result<ExitCode> {
    let vault = RawVault::load_dir(dir)
        .with_context(|| format!("reading vault directory {}", dir.display()))?;
    let report = validate(&vault, Mode::Plaintext);
    print_report(&report);
    if !report.is_valid() {
        bail!("refusing to export an invalid vault (fix the errors above)");
    }

    eprintln!(
        "This export is protected by the passphrase ALONE — no recovery key can\n\
         coexist with it (§6.4). Its security rests entirely on passphrase strength\n\
         against offline brute force: use six or more random words."
    );
    let passphrase = rpassword::prompt_password("passphrase: ")?;
    let confirm = rpassword::prompt_password("confirm passphrase: ")?;
    if passphrase != confirm {
        bail!("passphrases do not match");
    }
    if passphrase.len() < 12 {
        bail!("passphrase too short for an export whose security is the passphrase alone");
    }

    let recipient = age::scrypt::Recipient::new(passphrase.into());
    let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(recipient)];
    pack(&vault, &recipients, output)?;
    println!(
        "exported {} document{} → {} (scrypt-only; opens with `age -d` + passphrase)",
        vault.documents.len(),
        if vault.documents.len() == 1 { "" } else { "s" },
        output.display()
    );
    Ok(ExitCode::SUCCESS)
}

// ============================ shared plumbing ===============================

/// Load a vault from either physical form (§5), returning the mode for
/// mode-dependent validation findings.
fn load_vault(
    path: &Path,
    identity_paths: &[PathBuf],
    max_size_mib: u64,
) -> Result<(RawVault, Mode)> {
    if path.is_dir() {
        let vault = RawVault::load_dir(path)
            .with_context(|| format!("reading vault directory {}", path.display()))?;
        return Ok((vault, Mode::Plaintext));
    }

    let limits = ReadLimits {
        max_total_bytes: max_size_mib * 1024 * 1024,
        ..ReadLimits::default()
    };
    let stanzas = scan_header_stanzas(path)?;
    let scrypt_only = !stanzas.is_empty() && stanzas.iter().all(|s| s == "scrypt");

    let identities: Vec<Box<dyn age::Identity>> = if scrypt_only {
        let passphrase = rpassword::prompt_password("passphrase: ")?;
        vec![Box::new(age::scrypt::Identity::new(passphrase.into()))]
    } else {
        if identity_paths.is_empty() {
            bail!(
                "this vault is encrypted to X25519 recipients — pass -i <identity file> \
                 (the file age-keygen wrote, or a passphrase-encrypted .age of it)"
            );
        }
        let mut identities: Vec<Box<dyn age::Identity>> = Vec::new();
        for p in identity_paths {
            identities.extend(
                parse_identity_file(p)?
                    .into_identities()
                    .map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?,
            );
        }
        identities
    };

    let vault = read_container(path, &identities, limits)?;
    Ok((vault, Mode::Container { scrypt_only }))
}

/// Parse an identity file. If the file is itself an age file (a
/// passphrase-encrypted identity, §6.1), prompt for the passphrase and
/// unwrap it first.
fn parse_identity_file(path: &Path) -> Result<age::IdentityFile<age::NoCallbacks>> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let bytes = if bytes.starts_with(b"age-encryption.org/v1") {
        let prompt = format!("passphrase for {}: ", path.display());
        let passphrase = rpassword::prompt_password(prompt)?;
        let identity = age::scrypt::Identity::new(passphrase.into());
        let decryptor = age::Decryptor::new_buffered(BufReader::new(&bytes[..]))
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(|e| anyhow::anyhow!("unlocking {}: {e}", path.display()))?;
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut reader, &mut out)?;
        out
    } else {
        bytes
    };
    age::IdentityFile::from_buffer(BufReader::new(&bytes[..]))
        .with_context(|| format!("parsing identity file {}", path.display()))
}

fn print_report(report: &Report) {
    for finding in &report.findings {
        let tag = match finding.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        eprintln!("{tag}: {}: {}", finding.doc, finding.message);
    }
    let (e, w) = (report.error_count(), report.warning_count());
    if e == 0 && w == 0 {
        println!("vault is valid — no errors, no warnings");
    } else {
        println!(
            "{e} error{}, {w} warning{} — vault is {}",
            if e == 1 { "" } else { "s" },
            if w == 1 { "" } else { "s" },
            if e == 0 { "valid" } else { "INVALID" }
        );
    }
}
