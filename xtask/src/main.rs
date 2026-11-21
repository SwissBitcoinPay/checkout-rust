//! The repository's own tooling, run with `cargo xtask <command>` (.cargo/config.toml):
//!
//! - `cargo xtask check`: every check the CI runs on the pinned toolchain, one after the other,
//!   stopping at the first that fails: the pinned copy of the specification, the format, the
//!   lints, the tests, the README's examples, the documentation and the package as `cargo publish`
//!   would build it;
//! - `cargo xtask readme`: whether the README's Rust examples compile against the crate
//!   (xtask/src/readme.rs);
//! - `cargo xtask spec check`: whether `spec/` is the copy its PIN.json pins, file for file (the
//!   tests check it too);
//! - `cargo xtask spec import <checkout-spec clone>`: replaces `spec/` with the files of a clean
//!   clone of sattleme/checkout-spec, at the commit it is on, and writes PIN.json. Clone and check
//!   out the version yourself: no network.

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

mod pin;
mod readme;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("xtask/ is in the repository").to_path_buf()
}

fn spec_check() -> bool {
    let problems = pin::check_copy(&root().join("spec"));
    for problem in &problems {
        eprintln!("spec/: {problem}");
    }
    problems.is_empty()
}

/// Runs `cargo <args>` in the repository with `env`, saying what it runs.
fn cargo(args: &[&str], env: &[(&str, &str)]) -> bool {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    eprintln!("> cargo {}", args.join(" "));
    let mut command = Command::new(cargo);
    command.current_dir(root()).args(args);
    for (name, value) in env {
        command.env(name, value);
    }
    command.status().is_ok_and(|status| status.success())
}

fn readme_check() -> bool {
    match readme::check(&root()) {
        Ok(count) => {
            eprintln!("README.md: its {count} Rust blocks compile");
            true
        }
        Err(problem) => {
            eprintln!("{problem}");
            false
        }
    }
}

fn check() -> bool {
    eprintln!("> cargo xtask spec check");
    spec_check()
        && cargo(&["fmt", "--all", "--check"], &[])
        && cargo(&["clippy", "--workspace", "--all-targets", "--all-features", "--locked", "--", "-D", "warnings"], &[])
        && cargo(&["test", "--workspace", "--all-features", "--locked"], &[])
        && readme_check()
        && cargo(
            &["doc", "--package", "sattleme-checkout", "--no-deps", "--all-features", "--locked"],
            &[("RUSTDOCFLAGS", "-D warnings")],
        )
        // The package as `cargo publish` builds it, from the working tree as it is.
        && cargo(&["package", "--package", "sattleme-checkout", "--locked", "--allow-dirty"], &[])
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let ok = match args.as_slice() {
        ["check"] => check(),
        ["spec", "check"] => spec_check(),
        ["readme"] => readme_check(),
        ["spec", "import", clone] => match pin::import(Path::new(clone), &root().join("spec")) {
            Ok(imported) => {
                println!("spec/ is checkout-spec {} at {}", imported.version, imported.commit);
                true
            }
            Err(problem) => {
                eprintln!("{problem}");
                false
            }
        },
        _ => {
            eprintln!("Usage: cargo xtask check | readme | spec check | spec import <checkout-spec clone>");
            return ExitCode::from(2);
        }
    };
    if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}
