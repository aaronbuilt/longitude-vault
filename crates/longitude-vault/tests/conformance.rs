//! Conformance tests against the committed fixtures in `fixtures/`.
//! Any implementation of the spec should pass the equivalents of these.

use std::path::PathBuf;
use std::str::FromStr;

use longitude_vault::{
    pack, read_container, scan_header_stanzas, validate, ContainerError, Mode, RawVault, ReadLimits,
};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn fixture_identities() -> Vec<Box<dyn age::Identity>> {
    let contents = std::fs::read_to_string(fixtures().join("identities/fixture-key.txt"))
        .expect("run `cargo run -p fixture-gen` to generate fixtures first");
    let line = contents
        .lines()
        .find(|l| l.starts_with("AGE-SECRET-KEY-"))
        .expect("no AGE-SECRET-KEY line in fixture key");
    vec![Box::new(age::x25519::Identity::from_str(line).unwrap())]
}

#[test]
fn demo_dir_validates_clean() {
    let vault = RawVault::load_dir(&fixtures().join("valid/demo.lonvault")).unwrap();
    let report = validate(&vault, Mode::Plaintext);
    assert!(
        report.findings.is_empty(),
        "expected no findings: {:#?}",
        report.findings
    );
}

#[test]
fn demo_container_opens_and_validates_clean() {
    let vault = read_container(
        &fixtures().join("valid/demo.lon"),
        &fixture_identities(),
        ReadLimits::default(),
    )
    .unwrap();
    let report = validate(&vault, Mode::Container { scrypt_only: false });
    assert!(
        report.findings.is_empty(),
        "expected no findings: {:#?}",
        report.findings
    );
    // container and directory forms carry identical logical content (§5)
    let dir = RawVault::load_dir(&fixtures().join("valid/demo.lonvault")).unwrap();
    assert_eq!(vault.documents, dir.documents);
}

#[test]
fn export_container_opens_with_passphrase_and_warns() {
    let path = fixtures().join("valid/demo-export.lon");
    let stanzas = scan_header_stanzas(&path).unwrap();
    assert_eq!(stanzas, vec!["scrypt".to_string()]);

    let identities: Vec<Box<dyn age::Identity>> = vec![Box::new(age::scrypt::Identity::new(
        "longitude-fixture-passphrase".to_string().into(),
    ))];
    let vault = read_container(&path, &identities, ReadLimits::default()).unwrap();
    let report = validate(&vault, Mode::Container { scrypt_only: true });
    assert!(report.is_valid());
    assert_eq!(report.warning_count(), 1, "{:#?}", report.findings);
}

type RejectionCheck = fn(&ContainerError) -> bool;

#[test]
fn hostile_fixtures_are_rejected() {
    let cases: &[(&str, RejectionCheck)] = &[
        ("traversal.lon", |e| {
            matches!(e, ContainerError::PathTraversal(_))
        }),
        ("absolute.lon", |e| {
            matches!(e, ContainerError::AbsolutePath(_))
        }),
        ("symlink.lon", |e| {
            matches!(e, ContainerError::ForbiddenEntryType(..))
        }),
        ("hardlink.lon", |e| {
            matches!(e, ContainerError::ForbiddenEntryType(..))
        }),
        ("duplicate.lon", |e| {
            matches!(e, ContainerError::DuplicateEntry(_))
        }),
        ("badname.lon", |e| {
            matches!(e, ContainerError::FilenameGrammar(_))
        }),
        ("bomb.lon", |e| {
            matches!(
                e,
                ContainerError::DocTooLarge(..) | ContainerError::SizeCeiling(_)
            )
        }),
    ];
    let identities = fixture_identities();
    for (name, expected) in cases {
        let result = read_container(
            &fixtures().join("hostile").join(name),
            &identities,
            ReadLimits::default(),
        );
        match result {
            Ok(_) => panic!("{name}: hostile container was accepted"),
            Err(e) => assert!(expected(&e), "{name}: rejected with wrong error: {e}"),
        }
    }
}

#[test]
fn streaming_ceiling_triggers_even_with_large_doc_allowance() {
    // With the per-document limit raised out of the way, the incremental
    // decompressed-size ceiling must still stop the 64 MiB bomb.
    let limits = ReadLimits {
        max_total_bytes: 4 * 1024 * 1024,
        max_doc_bytes: u64::MAX,
        ..ReadLimits::default()
    };
    let result = read_container(
        &fixtures().join("hostile/bomb.lon"),
        &fixture_identities(),
        limits,
    );
    assert!(
        matches!(result, Err(ContainerError::SizeCeiling(_))),
        "expected SizeCeiling, got {result:?}"
    );
}

#[test]
fn pack_roundtrip_preserves_documents_and_is_reproducible() {
    let vault = RawVault::load_dir(&fixtures().join("valid/demo.lonvault")).unwrap();

    // reproducible archive (§5.2): same logical content ⇒ same bytes
    let a = longitude_vault::build_archive(&vault).unwrap();
    let b = longitude_vault::build_archive(&vault).unwrap();
    assert_eq!(a, b);

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("roundtrip.lon");
    let identities = fixture_identities();
    let recipient = std::fs::read_to_string(fixtures().join("identities/fixture-key.pub"))
        .unwrap()
        .trim()
        .parse::<age::x25519::Recipient>()
        .unwrap();
    let recipients: Vec<Box<dyn age::Recipient + Send>> = vec![Box::new(recipient)];
    pack(&vault, &recipients, &out).unwrap();

    let reread = read_container(&out, &identities, ReadLimits::default()).unwrap();
    assert_eq!(vault.documents, reread.documents);
}

#[test]
fn wrong_key_is_refused() {
    let identities: Vec<Box<dyn age::Identity>> = vec![Box::new(age::x25519::Identity::generate())];
    let result = read_container(
        &fixtures().join("valid/demo.lon"),
        &identities,
        ReadLimits::default(),
    );
    assert!(matches!(result, Err(ContainerError::NoMatchingKey)));
}

/// String-patch one document of a loaded vault (tests only).
fn patch(vault: &mut longitude_vault::RawVault, path: &str, from: &str, to: &str) {
    let doc = vault
        .documents
        .iter_mut()
        .find(|d| d.path == path)
        .unwrap_or_else(|| panic!("no {path} in demo vault"));
    let text = String::from_utf8(doc.bytes.clone()).unwrap();
    assert!(text.contains(from), "{path} does not contain {from:?}");
    doc.bytes = text.replace(from, to).into_bytes();
}

#[test]
fn guardrail_without_a_split_is_invalid() {
    let mut vault = RawVault::load_dir(&fixtures().join("valid/demo.lonvault")).unwrap();
    patch(
        &mut vault,
        "scenarios/stay-home.toml",
        "strategy = \"constant-dollar\"",
        "strategy = \"discretionary-guardrail\"",
    );
    let report = validate(&vault, Mode::Plaintext);
    assert!(!report.is_valid(), "{:#?}", report.findings);

    // exactly one split form makes it clean again
    let mut vault = RawVault::load_dir(&fixtures().join("valid/demo.lonvault")).unwrap();
    patch(
        &mut vault,
        "scenarios/stay-home.toml",
        "strategy = \"constant-dollar\"",
        "strategy = \"discretionary-guardrail\"\nessential_fraction = \"0.5\"",
    );
    let report = validate(&vault, Mode::Plaintext);
    assert!(report.findings.is_empty(), "{:#?}", report.findings);

    // a cut outside [0, 1] is an error
    let mut vault = RawVault::load_dir(&fixtures().join("valid/demo.lonvault")).unwrap();
    patch(
        &mut vault,
        "scenarios/stay-home.toml",
        "strategy = \"constant-dollar\"",
        "strategy = \"discretionary-guardrail\"\nessential_fraction = \"0.5\"\nbear_cut = \"1.5\"",
    );
    let report = validate(&vault, Mode::Plaintext);
    assert!(!report.is_valid(), "{:#?}", report.findings);
}

#[test]
fn legacy_lifestyle_alias_warns_but_stays_valid() {
    let mut vault = RawVault::load_dir(&fixtures().join("valid/demo.lonvault")).unwrap();
    patch(
        &mut vault,
        "profile.toml",
        "lifestyle = \"comfort\"",
        "lifestyle = \"comfortable\"",
    );
    let report = validate(&vault, Mode::Plaintext);
    assert!(report.is_valid());
    assert_eq!(report.warning_count(), 1, "{:#?}", report.findings);
    assert!(
        format!("{:?}", report.findings).contains("legacy alias"),
        "{:#?}",
        report.findings
    );
}
