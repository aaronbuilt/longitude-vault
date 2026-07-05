//! In-memory vault representation and plaintext-mode (directory) loading.

use std::fs;
use std::io;
use std::path::Path;

/// One file in a vault, path relative to the vault root, `/`-separated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub path: String,
    pub bytes: Vec<u8>,
}

/// A loaded vault: every non-dotfile under the root, sorted by path.
#[derive(Debug, Default)]
pub struct RawVault {
    pub documents: Vec<Document>,
}

impl RawVault {
    pub fn get(&self, path: &str) -> Option<&Document> {
        self.documents.iter().find(|d| d.path == path)
    }

    /// Load a plaintext-mode vault from a directory (§5.1). Dotfiles and
    /// dot-directories are not part of the vault and are skipped.
    pub fn load_dir(root: &Path) -> io::Result<RawVault> {
        let mut documents = Vec::new();
        walk(root, "", &mut documents)?;
        documents.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(RawVault { documents })
    }
}

fn walk(dir: &Path, prefix: &str, documents: &mut Vec<Document>) -> io::Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<io::Result<_>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("non-UTF-8 filename under {}", dir.display()),
            ));
        };
        if name.starts_with('.') {
            continue; // §5.1: dotfiles are not part of the vault
        }
        let path = entry.path();
        let rel = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        if path.is_dir() {
            walk(&path, &rel, documents)?;
        } else if path.is_file() {
            documents.push(Document {
                path: rel,
                bytes: fs::read(&path)?,
            });
        }
    }
    Ok(())
}
