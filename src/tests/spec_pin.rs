//! The pinned copy of the specification (spec/, PORTING.md of checkout-spec): every file of
//! spec/PIN.json is there with its SHA-256, and nothing else. It changes only by taking a newer
//! version of checkout-spec (`cargo xtask spec import <clone>`), never by hand.

#[path = "../../xtask/src/pin.rs"]
#[allow(dead_code, unreachable_pub)]
mod pin;

use super::support::vectors::root;

#[test]
fn spec_is_the_copy_pin_json_pins() {
    assert_eq!(pin::check_copy(&root().join("spec")), Vec::<String>::new());
}

#[test]
fn pin_json_names_the_specification_of_this_version() {
    let pin = super::support::vectors::spec("PIN.json");
    use super::support::vectors::Field;
    assert_eq!(pin.text("repository"), "https://github.com/sattleme/checkout-spec");
    assert_eq!(pin.text("commit"), "1bd7966d0cff77c2538c00e8929b65f0796d9220");
    assert_eq!(pin.text("version"), "1.0.0");
    assert_eq!(pin.int("protocol"), 1);
}

#[test]
fn the_check_tells_a_changed_file_a_missing_one_and_an_extra_one() {
    let scratch = root().join("target").join("spec-pin-test");
    let _ = std::fs::remove_dir_all(&scratch);
    let copy = scratch.join("spec");
    std::fs::create_dir_all(copy.join("vectors")).unwrap();
    std::fs::copy(root().join("spec/PIN.json"), copy.join("PIN.json")).unwrap();
    // Every file but SPEC.md, which is missing; PORTING.md changed; one more file.
    let pin = super::support::vectors::spec("PIN.json");
    if let Some(files) = pin.get("files").and_then(crate::json::Json::as_object) {
        for (name, _) in files.iter() {
            let name = name.as_str().unwrap();
            if name == "SPEC.md" {
                continue;
            }
            let target = copy.join(name);
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::copy(root().join("spec").join(name), &target).unwrap();
        }
    }
    std::fs::write(copy.join("PORTING.md"), "changed").unwrap();
    std::fs::write(copy.join("vectors/extra.json"), "{}").unwrap();
    let problems = pin::check_copy(&copy);
    let _ = std::fs::remove_dir_all(&scratch);
    assert_eq!(
        problems,
        vec![
            "PORTING.md differs from PIN.json".to_owned(),
            "SPEC.md is missing".to_owned(),
            "vectors/extra.json is not in PIN.json".to_owned(),
        ]
    );
}
