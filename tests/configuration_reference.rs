#[path = "../examples/support/config_reference.rs"]
mod reference;

#[test]
fn application_environment_examples_match_every_supported_setting() {
    reference::synchronize(true).unwrap();
}

#[test]
fn stack_examples_match_and_document_all_substitutions_without_active_app_overrides() {
    let compose = include_str!("../docker-compose.example.yml");
    assert_eq!(compose, include_str!("../portainer-stack.example.yml"));
    let documentation = include_str!("../CONFIGURATION.md");
    let dotenv = include_str!("../.env.example");
    for tail in compose.split("${").skip(1) {
        let name = tail.split([':', '}']).next().unwrap();
        assert!(
            documentation.contains(&format!("`{name}`")),
            "Undocumented stack variable {name}"
        );
        assert!(
            dotenv.lines().any(|line| line
                .trim_start_matches("# ")
                .starts_with(&format!("{name}="))),
            "Missing .env example for {name}"
        );
    }
    let application = compose
        .split("  qbittorent-intake-clamd:\n")
        .next()
        .unwrap();
    assert!(
        !application.contains("\n    environment:"),
        "Example must not lock UI settings by activating default TI_* overrides"
    );
    let binds = compose
        .lines()
        .filter(|line| *line == "      - type: bind")
        .count();
    let fail_if_missing = compose
        .lines()
        .filter(|line| *line == "          create_host_path: false")
        .count();
    assert!(binds > 0);
    assert_eq!(
        binds, fail_if_missing,
        "Every active bind must reject missing host storage"
    );
    let defaults: serde_json::Value =
        serde_json::from_str(include_str!("../resources/defaults.json")).unwrap();
    for name in defaults.as_object().unwrap().keys() {
        let variable = format!("TI_{}=", name.to_ascii_uppercase());
        assert!(
            !dotenv.lines().any(|line| line.starts_with(&variable)),
            "Application defaults must remain inactive in .env.example"
        );
    }
}

#[test]
fn every_explicit_sidecar_environment_variable_is_documented() {
    let source = include_str!("../src/bin/clamd-sidecar.rs");
    let documentation = include_str!("../CONFIGURATION.md");
    let compose = include_str!("../docker-compose.example.yml");
    let dotenv = include_str!("../.env.example");
    for read in source.split("std::env::var(\"").skip(1) {
        let name = read.split('"').next().unwrap();
        assert!(
            documentation.contains(&format!("`{name}`")),
            "Undocumented sidecar variable {name}"
        );
        assert!(
            compose.contains(&format!("{name}:")),
            "Missing stack reference for {name}"
        );
        assert!(
            dotenv.lines().any(|line| line
                .trim_start_matches("# ")
                .starts_with(&format!("{name}="))),
            "Missing .env example for {name}"
        );
    }
}
