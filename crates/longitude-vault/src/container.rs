//! Encrypted container mode: `vault.lon = age(zstd(tar(documents)))` (§5.2),
//! with the §5.4 untrusted-container reading rules enforced while streaming.

use std::collections::{BTreeSet, HashSet};
use std::error::Error as StdError;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;

use crate::grammar;
use crate::vault::{Document, RawVault};
use crate::RECOGNIZED_DIRS;

#[derive(Debug, thiserror::Error)]
pub enum ContainerError {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("not an age file (missing age-encryption.org/v1 header)")]
    NotAge,
    #[error("no identity matched this vault's recipients")]
    NoMatchingKey,
    #[error("age decryption failed: {0}")]
    Decrypt(String),
    #[error("age encryption failed: {0}")]
    Encrypt(String),
    #[error("archive entry {0:?}: absolute paths are forbidden (§5.4)")]
    AbsolutePath(String),
    #[error("archive entry {0:?}: `..` path segments are forbidden (§5.4)")]
    PathTraversal(String),
    #[error("archive entry {0:?}: malformed path (§5.4)")]
    MalformedPath(String),
    #[error(
        "archive entry {0:?}: entry type {1} is forbidden — only regular files \
         and directories are allowed (§5.4)"
    )]
    ForbiddenEntryType(String, String),
    #[error("archive contains two entries named {0:?} (§5.4)")]
    DuplicateEntry(String),
    #[error("archive entry {0:?}: filename violates the §3.2/§5.4 grammar")]
    FilenameGrammar(String),
    #[error("decompressed size exceeds the {0}-byte ceiling (§5.4 resource limits)")]
    SizeCeiling(u64),
    #[error("archive has more than {0} entries (§5.4 resource limits)")]
    TooManyEntries(usize),
    #[error("archive entry {0:?} exceeds the {1}-byte per-document limit (§5.4 resource limits)")]
    DocTooLarge(String, u64),
}

/// §5.4 resource limits. Defaults are deliberately generous for a personal
/// financial vault; callers MAY expose overrides to the user.
#[derive(Debug, Clone, Copy)]
pub struct ReadLimits {
    /// Ceiling on total decompressed bytes, checked while streaming.
    pub max_total_bytes: u64,
    /// Maximum number of archive entries.
    pub max_entries: usize,
    /// Maximum size of a single document.
    pub max_doc_bytes: u64,
}

impl Default for ReadLimits {
    fn default() -> Self {
        ReadLimits {
            max_total_bytes: 256 * 1024 * 1024,
            max_entries: 10_000,
            max_doc_bytes: 8 * 1024 * 1024,
        }
    }
}

/// Marker error surfaced through the tar/zstd layers when the streaming
/// decompression ceiling is hit.
#[derive(Debug)]
struct CeilingHit(u64);

impl fmt::Display for CeilingHit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "decompressed size exceeds the {}-byte ceiling", self.0)
    }
}

impl StdError for CeilingHit {}

/// Enforces the decompressed-size ceiling incrementally while streaming.
struct CeilingReader<R> {
    inner: R,
    ceiling: u64,
    remaining: u64,
}

impl<R: Read> Read for CeilingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n as u64 > self.remaining {
            return Err(io::Error::other(CeilingHit(self.ceiling)));
        }
        self.remaining -= n as u64;
        Ok(n)
    }
}

fn map_io(e: io::Error, ceiling: u64) -> ContainerError {
    if e.get_ref().is_some_and(|r| r.is::<CeilingHit>()) {
        ContainerError::SizeCeiling(ceiling)
    } else {
        ContainerError::Io(e)
    }
}

/// Scan the (plaintext, pre-payload) age header and return the stanza tags,
/// e.g. `["X25519", "X25519"]` or `["scrypt"]`. Used to distinguish a
/// passphrase-only export vault (§6.4) from a standard recipient vault
/// without attempting decryption.
pub fn scan_header_stanzas(path: &Path) -> Result<Vec<String>, ContainerError> {
    scan_header_stanzas_from(BufReader::new(File::open(path)?))
}

/// [`scan_header_stanzas`] over any reader (see [`read_container_from`]).
pub fn scan_header_stanzas_from<R: BufRead>(reader: R) -> Result<Vec<String>, ContainerError> {
    let mut lines = reader.lines();
    match lines.next() {
        Some(Ok(first)) if first.trim_end() == "age-encryption.org/v1" => {}
        _ => return Err(ContainerError::NotAge),
    }
    let mut tags = Vec::new();
    for line in lines {
        let line = line.map_err(|_| ContainerError::NotAge)?;
        if let Some(rest) = line.strip_prefix("-> ") {
            let tag = rest.split_whitespace().next().unwrap_or("");
            tags.push(tag.to_string());
        } else if line.starts_with("---") {
            return Ok(tags);
        }
        // other lines are wrapped stanza bodies; skip
    }
    Err(ContainerError::NotAge)
}

/// Decrypt and unpack a `.lon` container into memory, enforcing every §5.4
/// rule: entry-path hygiene, entry types, duplicates, filename grammar, and
/// resource limits (checked incrementally while streaming).
pub fn read_container(
    path: &Path,
    identities: &[Box<dyn age::Identity>],
    limits: ReadLimits,
) -> Result<RawVault, ContainerError> {
    let file = File::open(path)?;
    read_container_from(BufReader::new(file), identities, limits)
}

/// [`read_container`] over any reader — for callers whose container bytes
/// never touch a filesystem (a browser passes them across the wasm boundary).
pub fn read_container_from<R: BufRead>(
    reader: R,
    identities: &[Box<dyn age::Identity>],
    limits: ReadLimits,
) -> Result<RawVault, ContainerError> {
    let decryptor = age::Decryptor::new_buffered(reader).map_err(|e| match e {
        age::DecryptError::InvalidHeader => ContainerError::NotAge,
        e => ContainerError::Decrypt(e.to_string()),
    })?;
    let plaintext = decryptor
        .decrypt(identities.iter().map(|i| i.as_ref()))
        .map_err(|e| match e {
            age::DecryptError::NoMatchingKeys => ContainerError::NoMatchingKey,
            e => ContainerError::Decrypt(e.to_string()),
        })?;
    let zstd = zstd::stream::read::Decoder::new(plaintext)?;
    let ceiling = CeilingReader {
        inner: zstd,
        ceiling: limits.max_total_bytes,
        remaining: limits.max_total_bytes,
    };

    let mut archive = tar::Archive::new(ceiling);
    let mut seen: HashSet<String> = HashSet::new();
    let mut documents = Vec::new();

    for (index, entry) in archive
        .entries()
        .map_err(|e| map_io(e, limits.max_total_bytes))?
        .enumerate()
    {
        if index >= limits.max_entries {
            return Err(ContainerError::TooManyEntries(limits.max_entries));
        }
        let mut entry = entry.map_err(|e| map_io(e, limits.max_total_bytes))?;

        let raw_path = entry.path_bytes().into_owned();
        let lossy = String::from_utf8_lossy(&raw_path).into_owned();

        let entry_type = entry.header().entry_type();
        let is_dir = entry_type == tar::EntryType::Directory;
        if !(entry_type == tar::EntryType::Regular || is_dir) {
            return Err(ContainerError::ForbiddenEntryType(
                lossy,
                format!("{entry_type:?}"),
            ));
        }

        // §5.4 grammar note: the restricted grammar prevents case-collision
        // and Unicode-normalization aliasing, so paths must be valid UTF-8
        // to be checkable at all.
        let Ok(path_str) = std::str::from_utf8(&raw_path) else {
            return Err(ContainerError::FilenameGrammar(lossy));
        };
        let normalized = validate_entry_path(path_str, is_dir)?;
        if !seen.insert(normalized.clone()) {
            return Err(ContainerError::DuplicateEntry(normalized));
        }
        if is_dir {
            continue;
        }
        if entry.size() > limits.max_doc_bytes {
            return Err(ContainerError::DocTooLarge(
                normalized,
                limits.max_doc_bytes,
            ));
        }
        let mut bytes = Vec::with_capacity(entry.size() as usize);
        entry
            .read_to_end(&mut bytes)
            .map_err(|e| map_io(e, limits.max_total_bytes))?;
        documents.push(Document {
            path: normalized,
            bytes,
        });
    }

    documents.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(RawVault { documents })
}

/// Validate one archive entry path per §5.4 and return it normalized
/// (no trailing slash).
fn validate_entry_path(path: &str, is_dir: bool) -> Result<String, ContainerError> {
    let owned = || path.to_string();
    if path.starts_with('/') {
        return Err(ContainerError::AbsolutePath(owned()));
    }
    let normalized = path.strip_suffix('/').unwrap_or(path);
    if normalized.is_empty() {
        return Err(ContainerError::MalformedPath(owned()));
    }
    let segments: Vec<&str> = normalized.split('/').collect();
    for seg in &segments {
        if *seg == ".." {
            return Err(ContainerError::PathTraversal(owned()));
        }
        if seg.is_empty() || *seg == "." {
            return Err(ContainerError::MalformedPath(owned()));
        }
    }

    // Filename grammar applies within the §2 directories; entries under
    // unrecognized top-level directories flow through per §5.1 but remain
    // subject to the entry rules above.
    if RECOGNIZED_DIRS.contains(&segments[0]) {
        if is_dir {
            if segments.len() > 1 {
                return Err(ContainerError::FilenameGrammar(owned()));
            }
        } else {
            if segments.len() != 2 {
                return Err(ContainerError::FilenameGrammar(owned()));
            }
            let name = segments[1];
            let ok = match segments[0] {
                "snapshots" => name
                    .strip_suffix(".toml")
                    .is_some_and(grammar::is_date_stem),
                "notes" => name.strip_suffix(".md").is_some_and(grammar::is_slug),
                _ => name.strip_suffix(".toml").is_some_and(grammar::is_slug),
            };
            if !ok {
                return Err(ContainerError::FilenameGrammar(owned()));
            }
        }
    }
    Ok(normalized.to_string())
}

/// Build the reproducible tar archive for a vault (§5.2): entries in sorted
/// path order, uid/gid 0, mode 0644 files / 0755 directories, mtime 0.
pub fn build_archive(vault: &RawVault) -> io::Result<Vec<u8>> {
    // Directory entries derived from document paths, so identical logical
    // content yields identical archives regardless of source layout.
    let mut dirs: BTreeSet<String> = BTreeSet::new();
    for doc in &vault.documents {
        let mut prefix = String::new();
        for seg in doc
            .path
            .split('/')
            .rev()
            .skip(1)
            .collect::<Vec<_>>()
            .iter()
            .rev()
        {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(seg);
            dirs.insert(prefix.clone());
        }
    }

    enum Item<'a> {
        Dir(String),
        File(&'a Document),
    }
    let mut items: Vec<(String, Item)> = Vec::new();
    for d in &dirs {
        items.push((format!("{d}/"), Item::Dir(format!("{d}/"))));
    }
    for doc in &vault.documents {
        items.push((doc.path.clone(), Item::File(doc)));
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));

    let mut builder = tar::Builder::new(Vec::new());
    for (_, item) in items {
        let mut header = tar::Header::new_ustar();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        match item {
            Item::Dir(path) => {
                header.set_entry_type(tar::EntryType::Directory);
                header.set_mode(0o755);
                header.set_size(0);
                builder.append_data(&mut header, path, io::empty())?;
            }
            Item::File(doc) => {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_mode(0o644);
                header.set_size(doc.bytes.len() as u64);
                builder.append_data(&mut header, &doc.path, doc.bytes.as_slice())?;
            }
        }
    }
    builder.into_inner()
}

/// Compression level within the spec's SHOULD range of 9–12 (§5.2).
pub const ZSTD_LEVEL: i32 = 9;

/// Pack a vault into a `.lon` container encrypted to `recipients`, written
/// atomically (temp file in the same directory, then rename — §5.2).
pub fn pack(
    vault: &RawVault,
    recipients: &[Box<dyn age::Recipient + Send>],
    out: &Path,
) -> Result<(), ContainerError> {
    let bytes = pack_bytes(vault, recipients)?;

    let dir = out.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        out.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "vault.lon".into()),
        std::process::id()
    ));
    let result = (|| -> Result<(), ContainerError> {
        let file = File::create(&tmp)?;
        let mut file = io::BufWriter::new(file);
        file.write_all(&bytes)?;
        let file = file.into_inner().map_err(io::Error::from)?;
        file.sync_all()?;
        fs::rename(&tmp, out)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// [`pack`] to bytes — the container as it would be written, for callers
/// that store it somewhere other than a filesystem path (see
/// [`read_container_from`]).
pub fn pack_bytes(
    vault: &RawVault,
    recipients: &[Box<dyn age::Recipient + Send>],
) -> Result<Vec<u8>, ContainerError> {
    let archive = build_archive(vault)?;
    let compressed = zstd::stream::encode_all(archive.as_slice(), ZSTD_LEVEL)?;

    let encryptor = age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref() as _))
        .map_err(|e| ContainerError::Encrypt(e.to_string()))?;
    let mut out = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut out)
        .map_err(|e| ContainerError::Encrypt(e.to_string()))?;
    writer.write_all(&compressed)?;
    writer
        .finish()
        .map_err(|e| ContainerError::Encrypt(e.to_string()))?;
    Ok(out)
}

/// Write an in-memory vault out as a plaintext-mode directory. Paths are
/// assumed already validated (documents from `read_container` are).
pub fn write_dir(vault: &RawVault, dest: &Path) -> io::Result<()> {
    fs::create_dir_all(dest)?;
    for doc in &vault.documents {
        let target = dest.join(&doc.path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, &doc.bytes)?;
    }
    Ok(())
}
