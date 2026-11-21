//! The pinned copy of the specification (sattleme/checkout-spec, its PORTING.md: "The pinned copy
//! of the specification"): `spec/` holds the files its manifest.json lists, unchanged, and
//! `spec/PIN.json` says which commit they come from, with the SHA-256 of each.
//!
//! Shared by `cargo xtask spec` and the crate's test of the copy (src/tests/spec_pin.rs), which
//! includes this file as it is.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use sha2::{Digest, Sha256};

/// The repository the copy comes from.
pub const REPOSITORY: &str = "https://github.com/sattleme/checkout-spec";
/// The file next to the copy that pins it.
pub const PIN: &str = "PIN.json";

fn sha256(path: &Path) -> std::io::Result<String> {
    let digest = Sha256::digest(fs::read(path)?);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        write!(hex, "{byte:02x}").expect("writing to a String does not fail");
    }
    Ok(hex)
}

/// Every file under `dir`, as paths relative to it with `/`, sorted.
fn files_under(dir: &Path) -> std::io::Result<Vec<String>> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in fs::read_dir(&current)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                pending.push(path);
            } else {
                let relative = path.strip_prefix(dir).expect("a file under the directory walked");
                let parts: Vec<String> = relative
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect();
                found.push(parts.join("/"));
            }
        }
    }
    found.sort();
    Ok(found)
}

fn is_commit(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|commit| {
        commit.len() == 40 && commit.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// What differs between the copy in `copy` and its PIN.json: empty when the copy is the pinned one
/// (every file of PIN.json there with its SHA-256, and no other file but PIN.json).
pub fn check_copy(copy: &Path) -> Vec<String> {
    let pin_path = copy.join(PIN);
    let pin: Value = match fs::read(&pin_path).map(|bytes| serde_json::from_slice::<Value>(&bytes)) {
        Ok(Ok(pin)) => pin,
        Ok(Err(_)) => return vec![format!("{PIN} is not JSON")],
        Err(_) => return vec![format!("{PIN} is missing")],
    };
    let mut problems = Vec::new();
    if pin.get("repository").and_then(Value::as_str) != Some(REPOSITORY) {
        problems.push(format!("{PIN}: repository is not {REPOSITORY}"));
    }
    if !is_commit(pin.get("commit")) {
        problems.push(format!("{PIN}: commit is not a commit"));
    }
    let empty = serde_json::Map::new();
    let files = pin.get("files").and_then(Value::as_object).unwrap_or(&empty);
    for (file, hash) in files {
        let path = copy.join(file);
        match sha256(&path) {
            Err(_) => problems.push(format!("{file} is missing")),
            Ok(actual) if Some(actual.as_str()) != hash.as_str() => {
                problems.push(format!("{file} differs from {PIN}"));
            }
            Ok(_) => {}
        }
    }
    match files_under(copy) {
        Ok(found) => {
            for file in found {
                if file != PIN && !files.contains_key(&file) {
                    problems.push(format!("{file} is not in {PIN}"));
                }
            }
        }
        Err(error) => problems.push(format!("{} cannot be read: {error}", copy.display())),
    }
    problems
}

/// What `import` read: the version and the commit of the copy.
pub struct Imported {
    /// manifest.json's `version`.
    pub version: String,
    /// The commit the clone is on.
    pub commit: String,
}

fn git(clone: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(clone)
        .args(args)
        .output()
        .map_err(|error| format!("git cannot run: {error}"))?;
    if !output.status.success() {
        return Err(format!("git {} failed in {}", args.join(" "), clone.display()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Replaces the copy in `copy` with the files of the clean clone `clone`, at the commit it is on,
/// and writes PIN.json. Its manifest.json must be its files'. Clone and check out the version
/// yourself: no network.
pub fn import(clone: &Path, copy: &Path) -> Result<Imported, String> {
    if !git(clone, &["status", "--porcelain"])?.is_empty() {
        return Err(format!("{} is not clean", clone.display()));
    }
    let commit = git(clone, &["rev-parse", "HEAD"])?;
    let manifest: Value = fs::read(clone.join("manifest.json"))
        .map_err(|error| format!("manifest.json cannot be read: {error}"))
        .and_then(|bytes| {
            serde_json::from_slice(&bytes).map_err(|error| format!("manifest.json: {error}"))
        })?;
    let files = manifest
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| "manifest.json has no files".to_owned())?;
    let mut sorted = BTreeMap::new();
    for (file, hash) in files {
        let hash = hash.as_str().ok_or_else(|| format!("manifest.json: {file} has no hash"))?;
        if sha256(&clone.join(file)).ok().as_deref() != Some(hash) {
            return Err(format!("{file} is not the manifest's"));
        }
        sorted.insert(file.clone(), hash.to_owned());
    }
    if copy.exists() {
        fs::remove_dir_all(copy).map_err(|error| format!("{} cannot be removed: {error}", copy.display()))?;
    }
    for file in sorted.keys() {
        let target: PathBuf = copy.join(file);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
        }
        fs::copy(clone.join(file), &target).map_err(|error| format!("{file} cannot be copied: {error}"))?;
    }
    let version = manifest.get("version").and_then(Value::as_str).unwrap_or_default().to_owned();
    let protocol = manifest.get("protocol").cloned().unwrap_or(Value::Null);
    // As checkout-node writes it (`JSON.stringify(pin, null, 2)`): these members in this order,
    // the files in the manifest's (sorted) order.
    let quote = |text: &str| Value::String(text.to_owned()).to_string();
    let mut text = String::from("{\n");
    writeln!(text, "  \"repository\": {},", quote(REPOSITORY)).expect("writing to a String");
    writeln!(text, "  \"commit\": {},", quote(&commit)).expect("writing to a String");
    writeln!(text, "  \"version\": {},", quote(&version)).expect("writing to a String");
    writeln!(text, "  \"protocol\": {protocol},").expect("writing to a String");
    text.push_str("  \"files\": {\n");
    let entries: Vec<String> =
        sorted.iter().map(|(file, hash)| format!("    {}: {}", quote(file), quote(hash))).collect();
    text.push_str(&entries.join(",\n"));
    text.push_str("\n  }\n}\n");
    fs::write(copy.join(PIN), text).map_err(|error| format!("PIN.json cannot be written: {error}"))?;
    Ok(Imported { version, commit })
}
