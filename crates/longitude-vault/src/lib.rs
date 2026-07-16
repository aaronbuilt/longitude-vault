//! Reference implementation of the Longitude vault format.
//!
//! A vault is a set of TOML documents (SPEC.md §2–§4) with two physical
//! forms: a plaintext directory (§5.1) and an encrypted `.lon` container,
//! `age(zstd(tar(documents)))` (§5.2). This crate loads both forms,
//! validates them per §8, and reads untrusted containers per §5.4.

pub mod container;
pub mod demo;
pub mod grammar;
pub mod report;
pub mod validate;
pub mod vault;

pub use container::{
    build_archive, pack, pack_bytes, read_container, read_container_from, scan_header_stanzas,
    scan_header_stanzas_from, ContainerError, ReadLimits,
};
pub use report::{Finding, Report, Severity};
pub use validate::{validate, Mode};
pub use vault::{Document, RawVault};

/// The format version this implementation writes.
pub const SCHEMA: &str = "0.1";

/// The highest schema MAJOR this implementation understands (§3.7).
pub const KNOWN_SCHEMA_MAJOR: u64 = 0;

/// Top-level directories defined by SPEC §2.
pub const RECOGNIZED_DIRS: &[&str] = &[
    "accounts",
    "snapshots",
    "scenarios",
    "overrides",
    "transactions",
    "notes",
];
