//! Notice coverage is checked without accessing local Cargo cache contents or
//! fetching other-platform dependencies during an ordinary offline test run.
use sha2::{Digest, Sha256};

#[test]
fn distributed_notices_match_the_lockfile_and_cover_every_registry_package() {
    let lockfile = include_str!("../Cargo.lock");
    let notices = include_str!("../THIRD_PARTY_LICENSES.txt");
    let hash = format!(
        "Lockfile SHA-256: {:x}",
        Sha256::digest(lockfile.as_bytes())
    );
    assert!(notices.contains(&hash), "Cargo.lock changed: run cargo fetch --locked then cargo run --example generate_third_party_licenses");
    let mut expected = 0;
    for package in lockfile.split("[[package]]").skip(1) {
        if !package
            .lines()
            .any(|line| line.starts_with("source = \"registry+"))
        {
            continue;
        }
        let field = |name: &str| {
            package
                .lines()
                .find_map(|line| {
                    line.strip_prefix(&format!("{name} = \""))
                        .and_then(|value| value.strip_suffix('"'))
                })
                .unwrap()
        };
        let name = field("name");
        let version = field("version");
        assert!(
            notices.contains(&format!("PACKAGE: {name} {version}\n")),
            "Missing notice inventory for {name} {version}"
        );
        expected += 1;
    }
    assert!(expected > 0);
    assert_eq!(
        notices
            .lines()
            .filter(|line| line.starts_with("PACKAGE: "))
            .count(),
        expected
    );
}
