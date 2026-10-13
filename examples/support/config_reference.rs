//! One rendering of the embedded settings schema feeds the public examples.
//! This runs only as a maintenance example or test, never in the controller.
use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{fs, path::Path};

fn value_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "optional string",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "nonnegative integer",
        Value::Array(_) => "JSON array",
        _ => "string",
    }
}

fn blocks() -> Result<(String, String, String)> {
    let defaults: Value = serde_json::from_str(include_str!("../../resources/defaults.json"))?;
    let catalog: Value =
        serde_json::from_str(include_str!("../../resources/settings-catalog.json"))?;
    let defaults = defaults.as_object().context("defaults must be an object")?;
    let specs = catalog["specs"]
        .as_array()
        .context("specs must be an array")?;
    if defaults.len() != specs.len() {
        bail!("Every application setting needs exactly one catalog description");
    }
    let mut yaml = String::from("    # environment:\n");
    let mut dotenv = String::new();
    let mut table = String::from(
        "| Variable | Type | Built-in default | Meaning and limits |\n| --- | --- | --- | --- |\n",
    );
    for (name, default) in defaults {
        let matching: Vec<_> = specs
            .iter()
            .filter(|spec| spec["name"] == name.as_str())
            .collect();
        if matching.len() != 1 {
            bail!("Setting {name} must have exactly one catalog entry");
        }
        let description = matching[0]["description"]
            .as_str()
            .context("description is missing")?;
        let variable = format!("TI_{}", name.to_ascii_uppercase());
        let kind = value_type(default);
        let shown_default = if default.is_null() {
            "unset".into()
        } else {
            default.to_string()
        };
        let mut meaning = description.to_owned();
        if default.is_number() {
            let range = &catalog["number_limits"][name];
            let minimum = range[0].as_u64().unwrap_or(1);
            meaning.push_str(&match range[1].as_u64() {
                Some(maximum) => format!(" Allowed: {minimum} through {maximum}."),
                None => format!(" Minimum: {minimum}."),
            });
        }
        yaml.push_str(&format!("    #   # {variable} | type: {kind} | default: {shown_default}\n    #   # {meaning}\n    #   {variable}: ${{{variable}:?set {variable} explicitly before enabling this override}}\n"));
        dotenv.push_str(&format!("# {variable} | type: {kind} | default: {shown_default}\n# {meaning}\n# {variable}={}\n", if default.is_null() { String::new() } else { default.to_string() }));
        table.push_str(&format!(
            "| `{variable}` | {kind} | `{shown_default}` | {} |\n",
            meaning.replace('|', "\\|")
        ));
    }
    Ok((yaml, dotenv, table))
}

fn replace_block(content: &str, begin: &str, end: &str, replacement: &str) -> Result<String> {
    if content.matches(begin).count() != 1 || content.matches(end).count() != 1 {
        bail!("Reference needs exactly one {begin} / {end} block");
    }
    let start = content.find(begin).unwrap() + begin.len();
    let finish = content.find(end).unwrap();
    if start >= finish {
        bail!("Reference block markers are out of order");
    }
    Ok(format!(
        "{}\n{replacement}{}",
        &content[..start],
        &content[finish..]
    ))
}

/// `check_only` compares generated text without writing; cargo test uses it to
/// catch added/changed settings whose public examples were not regenerated.
pub fn synchronize(check_only: bool) -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (yaml, dotenv, table) = blocks()?;
    for (file, begin, end, replacement) in [
        (
            "docker-compose.example.yml",
            "    # BEGIN GENERATED APPLICATION ENVIRONMENT",
            "    # END GENERATED APPLICATION ENVIRONMENT",
            yaml.as_str(),
        ),
        (
            "portainer-stack.example.yml",
            "    # BEGIN GENERATED APPLICATION ENVIRONMENT",
            "    # END GENERATED APPLICATION ENVIRONMENT",
            yaml.as_str(),
        ),
        (
            ".env.example",
            "# BEGIN GENERATED APPLICATION ENVIRONMENT",
            "# END GENERATED APPLICATION ENVIRONMENT",
            dotenv.as_str(),
        ),
        (
            "CONFIGURATION.md",
            "<!-- BEGIN GENERATED APPLICATION ENVIRONMENT -->",
            "<!-- END GENERATED APPLICATION ENVIRONMENT -->",
            table.as_str(),
        ),
    ] {
        let path = root.join(file);
        let current = fs::read_to_string(&path).with_context(|| format!("Read {file}"))?;
        let expected = replace_block(&current, begin, end, replacement)?;
        if expected != current {
            if check_only {
                bail!("{file} is stale; run cargo run --example generate_config_reference");
            }
            fs::write(path, expected)?;
        }
    }
    Ok(())
}
