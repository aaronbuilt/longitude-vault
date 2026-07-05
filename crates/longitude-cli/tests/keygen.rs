//! `longitude keygen` must produce a *standard* age identity — one our own
//! tooling round-trips and, crucially, one stock `age` can read. The stock-age
//! proof runs in CI's liberation job (where `age` is guaranteed installed); here
//! we prove the file shape and a full pack/unpack round trip with no external
//! tools, so these run everywhere.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_longitude");

fn workdir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(BIN)
        .args(args)
        .current_dir(dir)
        .output()
        .expect("failed to spawn longitude")
}

fn files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        for entry in fs::read_dir(&p).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out
}

#[test]
fn keygen_writes_a_standard_age_identity_file() {
    let dir = workdir("keygen_shape");
    let out = run(&dir, &["keygen", "-o", "id.txt"]);
    assert!(
        out.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let body = fs::read_to_string(dir.join("id.txt")).unwrap();
    let mut lines = body.lines();
    assert!(
        lines.next().unwrap().starts_with("# created: "),
        "missing `# created:` header:\n{body}"
    );
    let pub_line = lines.next().unwrap();
    assert!(
        pub_line.starts_with("# public key: age1"),
        "missing `# public key:` header:\n{body}"
    );
    assert!(
        body.contains("\nAGE-SECRET-KEY-1"),
        "missing AGE-SECRET-KEY line:\n{body}"
    );

    // The public key echoed to stderr matches the file's comment.
    let stderr = String::from_utf8_lossy(&out.stderr);
    let key = pub_line.trim_start_matches("# public key: ");
    assert!(
        stderr.contains(key),
        "stderr public key does not match the file's public key"
    );

    // Refuses to clobber an existing identity — overwriting a key is total
    // data loss (every vault encrypted to it becomes unopenable).
    let again = run(&dir, &["keygen", "-o", "id.txt"]);
    assert!(
        !again.status.success(),
        "keygen overwrote an existing identity file"
    );
}

#[test]
fn keygen_key_round_trips_through_pack_and_unpack() {
    let dir = workdir("keygen_roundtrip");
    assert!(run(&dir, &["keygen", "-o", "id.txt"]).status.success());
    assert!(run(&dir, &["vault", "init", "v", "--demo"])
        .status
        .success());
    assert!(
        run(&dir, &["vault", "pack", "v", "-o", "v.lon", "-i", "id.txt"])
            .status
            .success()
    );
    assert!(run(
        &dir,
        &["vault", "unpack", "v.lon", "-o", "back", "-i", "id.txt"]
    )
    .status
    .success());

    // Every document in the original vault comes back byte-identical — proof
    // the generated key both encrypts and decrypts.
    let orig = dir.join("v");
    let back = dir.join("back");
    let mut compared = 0;
    for path in files(&orig) {
        let rel = path.strip_prefix(&orig).unwrap();
        let restored = back.join(rel);
        assert!(
            restored.exists(),
            "document missing after round trip: {}",
            rel.display()
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            fs::read(&restored).unwrap(),
            "document differs after round trip: {}",
            rel.display()
        );
        compared += 1;
    }
    assert!(compared >= 1, "no documents were compared");
}
