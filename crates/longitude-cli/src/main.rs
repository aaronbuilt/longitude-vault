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
    /// Work with vaults
    #[command(subcommand)]
    Vault(VaultCommand),
    /// Deterministic single-scenario projection (the open engine core)
    Project {
        /// Vault directory or .lon file
        path: PathBuf,
        /// age identity file (repeatable); may itself be passphrase-encrypted (.age)
        #[arg(short, long)]
        identity: Vec<PathBuf>,
        /// Scenario id to project (default: the targeted scenario)
        #[arg(short, long)]
        scenario: Option<String>,
        /// Valuation month as YYYY-MM (default: the current month)
        #[arg(long)]
        now: Option<String>,
        /// Simple mode: the scenario's [withdrawal] strategy drives spending
        /// (ficalc-style) instead of the plan's expenses (engine spec §7.2)
        #[arg(long)]
        simple: bool,
        /// Print the year-by-year table
        #[arg(long)]
        table: bool,
        /// Decompressed-size ceiling in MiB (§5.4 resource limits)
        #[arg(long, default_value_t = 256)]
        max_size_mib: u64,
    },
    /// Generate an age identity — a standard age key file (opens with stock age too)
    Keygen {
        /// Write the identity here (default: stdout). The public key always goes
        /// to stderr, so `longitude keygen > identity.txt` captures only the key.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
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
        Command::Project {
            path,
            identity,
            scenario,
            now,
            simple,
            table,
            max_size_mib,
        } => cmd_project(
            &path,
            &identity,
            scenario.as_deref(),
            now.as_deref(),
            simple,
            table,
            max_size_mib,
        ),
        Command::Keygen { output } => cmd_keygen(output.as_deref()),
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
    println!("  longitude keygen -o identity.txt     # make a device key (keep it safe)");
    println!(
        "  longitude vault pack {} -o vault.lon -i identity.txt",
        dir.display()
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_keygen(output: Option<&Path>) -> Result<ExitCode> {
    use age::secrecy::ExposeSecret;

    let identity = age::x25519::Identity::generate();
    let public = identity.to_public();
    let created = humantime::format_rfc3339_seconds(std::time::SystemTime::now());

    // The standard age identity-file shape: two comment lines then the secret,
    // byte-for-byte what `age-keygen` writes. Nothing here is Longitude-specific
    // — stock age reads this file, and this is a convenience over `age-keygen`,
    // not a fork of it.
    let secret = identity.to_string();
    let body = format!(
        "# created: {created}\n# public key: {public}\n{}\n",
        secret.expose_secret()
    );

    match output {
        Some(path) => {
            if path.exists() {
                bail!(
                    "{} already exists — refusing to overwrite an identity file \
                     (overwriting a key locks you out of every vault encrypted to it)",
                    path.display()
                );
            }
            fs::write(path, &body)
                .with_context(|| format!("writing identity to {}", path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                    .with_context(|| format!("restricting permissions on {}", path.display()))?;
            }
            eprintln!("Public key: {public}");
            eprintln!(
                "wrote identity to {} — back it up; it is the only way to open \
                 vaults encrypted to it (§6.1)",
                path.display()
            );
        }
        None => {
            use std::io::Write;
            // Identity to stdout, public key to stderr — mirrors age-keygen, so
            // `longitude keygen > identity.txt` captures only the secret key.
            print!("{body}");
            std::io::stdout().flush().ok();
            eprintln!("Public key: {public}");
        }
    }
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

fn cmd_project(
    path: &Path,
    identity_paths: &[PathBuf],
    scenario_id: Option<&str>,
    now: Option<&str>,
    simple: bool,
    table: bool,
    max_size_mib: u64,
) -> Result<ExitCode> {
    let (vault, mode) = load_vault(path, identity_paths, max_size_mib)?;
    let report = validate(&vault, mode);
    if !report.is_valid() {
        print_report(&report);
        bail!("refusing to project an invalid vault (fix the errors above)");
    }

    let now = match now {
        Some(s) => parse_month(s)?,
        None => current_month(),
    };
    let spending_mode = if simple {
        longitude_engine::SpendingMode::Simple
    } else {
        longitude_engine::SpendingMode::Plan
    };
    let model = longitude_engine::extract(&vault)?;
    let scenario = model.select_scenario(scenario_id)?;
    let projection = longitude_engine::project(&model, scenario, now, spending_mode)?;
    print_projection(&projection, &model.base_currency, table);
    Ok(ExitCode::SUCCESS)
}

fn parse_month(s: &str) -> Result<longitude_engine::Month> {
    let (y, m) = s
        .split_once('-')
        .ok_or_else(|| anyhow::anyhow!("--now must be YYYY-MM, got {s:?}"))?;
    let year: i32 = y.parse().context("--now year")?;
    let month: u8 = m.parse().context("--now month")?;
    if !(1..=12).contains(&month) {
        bail!("--now month must be 01–12");
    }
    Ok(longitude_engine::Month::from_ym(year, month))
}

fn current_month() -> longitude_engine::Month {
    // RFC 3339 is YYYY-MM-…, so the first seven characters are the month.
    let now = humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string();
    let year: i32 = now[0..4].parse().unwrap_or(2026);
    let month: u8 = now[5..7].parse().unwrap_or(1);
    longitude_engine::Month::from_ym(year, month)
}

fn fmt_money(v: f64, currency: &str) -> String {
    let negative = v < 0.0;
    let whole = v.abs().round() as u64;
    let digits = whole.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    format!("{}{} {}", if negative { "-" } else { "" }, out, currency)
}

fn print_projection(p: &longitude_engine::Projection, currency: &str, table: bool) {
    use rust_decimal::prelude::ToPrimitive;

    println!("Longitude — deterministic projection (open engine core)");
    println!("All figures are real (today's prices), in {currency}. Estimates, not advice.");
    println!();
    println!(
        "scenario         {} ({}{})",
        p.scenario_name,
        p.scenario_id,
        if p.targeted { ", targeted" } else { "" }
    );
    println!(
        "window           {} → {} ({} years)",
        p.start,
        p.start.plus_months(p.horizon_years as i32 * 12),
        p.horizon_years
    );
    println!();
    let as_of = p
        .valuation_as_of
        .map(|d| format!("  (snapshots as of {d})"))
        .unwrap_or_default();
    println!(
        "t₀ investable    {}{as_of}",
        fmt_money(p.t0_investable.to_f64().unwrap_or(0.0), currency)
    );
    match (&p.annual_spending, &p.strategy) {
        (Some(spend), _) => println!(
            "spending         {} / yr",
            fmt_money(spend.to_f64().unwrap_or(0.0), currency)
        ),
        (None, Some(s)) => {
            let params = match (s.rate, s.floor, s.ceiling) {
                (Some(r), None, None) => format!(" @ {:.1}%", r * 100.0),
                (Some(r), floor, ceiling) => format!(
                    " @ {:.1}% in [{} – {}]",
                    r * 100.0,
                    floor
                        .map(|f| fmt_money(f, currency))
                        .unwrap_or_else(|| "0".into()),
                    ceiling
                        .map(|c| fmt_money(c, currency))
                        .unwrap_or_else(|| "∞".into()),
                ),
                (None, _, _) => String::new(),
            };
            println!("spending         strategy-driven: {}{params}", s.slug);
            println!(
                "  first year     {} / yr",
                fmt_money(s.first_year, currency)
            );
            println!(
                "  across years   {} – {} / yr",
                fmt_money(s.min_year, currency),
                fmt_money(s.max_year, currency)
            );
        }
        (None, None) => {}
    }
    println!(
        "real return      {:.1}% / yr (blended)",
        p.blended_return * 100.0
    );
    match (p.swr, p.fi_number, p.score) {
        (Some(swr), Some(fi), Some(score)) => {
            println!(
                "SWR              {:.1}%  →  FI number {}",
                swr.to_f64().unwrap_or(0.0) * 100.0,
                fmt_money(fi.to_f64().unwrap_or(0.0), currency)
            );
            println!(
                "Longitude Score  {:.1}%  (investable ÷ FI number)",
                score * 100.0
            );
        }
        _ if p.strategy.is_some() => {
            println!("Longitude Score  (a plan concept — not computed in simple mode)")
        }
        _ => println!("SWR              (unavailable — no rate; Score skipped)"),
    }
    println!();
    match p.fi_month {
        Some(m) => println!("FI date          {m}  (portfolio first ≥ FI number)"),
        None => println!("FI date          not reached within the horizon"),
    }
    match p.depletion_month {
        Some(m) => {
            let tail = if p.recovered {
                "  — later income rebuilt the portfolio (recovered)"
            } else {
                ""
            };
            println!("depletion        {m}  (a withdrawal could not be met){tail}");
        }
        None => println!("depletion        none — the portfolio funds this plan to horizon"),
    }
    println!("end of horizon   {}", fmt_money(p.end_balance, currency));

    if table {
        println!();
        println!(
            "{:>6}  {:>14}  {:>14}  {:>16}",
            "year", "income", "expenses", "end balance"
        );
        for row in &p.years {
            println!(
                "{:>6}  {:>14}  {:>14}  {:>16}",
                row.year,
                fmt_money(row.income, currency),
                fmt_money(row.expenses, currency),
                fmt_money(row.end_balance, currency)
            );
        }
    }

    if !p.warnings.is_empty() {
        println!();
        for w in &p.warnings {
            eprintln!("note: {w}");
        }
    }
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
