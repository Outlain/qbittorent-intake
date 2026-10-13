//! Compatibility executable for deployments that use copying as a trusted hook.
//! Ordinary deployments can enable built-in copying and omit this executable.
use anyhow::{bail, Context, Result};
use std::{collections::HashMap, ffi::OsString, path::PathBuf, process::ExitCode};
use torrent_intake::workflow::{run_copy_hook, CopyHookRequest};

const DESTINATION_ROOT: &str = "/copy-target/intake-copies";
const HELP: &str = "Copy an already promoted payload without replacing existing content.

Usage: after-promotion-copy --source PATH --torrent-hash HASH --torrent-name NAME --job-id ID

Options:
  --destination PATH    Existing mounted directory (default: /copy-target/intake-copies)
  --source-root PATH    Routing root; requires --relative-path
  --relative-path PATH  Payload path beneath the routing root
  -h, --help            Show this help

The destination requires a readable .intake-copy-mount marker.
Without routing options, copies use intake-job-ID/PAYLOAD and the legacy receipt.";

fn main() -> ExitCode {
    let request = match parse_args(std::env::args_os().skip(1)) {
        Ok(Some(request)) => request,
        Ok(None) => {
            println!("{HELP}");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("{error:#}\n\n{HELP}");
            return ExitCode::from(2);
        }
    };
    // This is a short-lived, single-purpose process. Private files created by
    // the shared copier must not become readable through the caller's umask.
    unsafe {
        libc::umask(0o077);
    }
    match run_copy_hook(&request) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Copy hook failed: {error:#}. Source retained; no cleanup was performed.");
            ExitCode::FAILURE
        }
    }
}

/// Keep argument handling separate from copying so help and input errors never
/// inspect or modify source/destination storage. Both --key value and --key=value
/// are accepted, including names containing spaces or beginning with a hyphen.
fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<Option<CopyHookRequest>> {
    let mut args = args.into_iter();
    let mut values = HashMap::new();
    while let Some(argument) = args.next() {
        let text = argument
            .to_str()
            .context("option name must be valid UTF-8")?;
        if matches!(text, "-h" | "--help") {
            return Ok(None);
        }
        let (key, inline) = match text.split_once('=') {
            Some((key, value)) => (key, Some(OsString::from(value))),
            None => (text, None),
        };
        if !matches!(
            key,
            "--source"
                | "--destination"
                | "--torrent-hash"
                | "--torrent-name"
                | "--job-id"
                | "--source-root"
                | "--relative-path"
        ) {
            bail!("unknown option: {key}");
        }
        let value = inline
            .or_else(|| args.next())
            .with_context(|| format!("missing value for {key}"))?;
        values.insert(key.to_owned(), value);
    }
    let source = PathBuf::from(values.remove("--source").context("--source is required")?);
    let destination = values
        .remove("--destination")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DESTINATION_ROOT));
    let source_root = values.remove("--source-root").map(PathBuf::from);
    let relative_path = values.remove("--relative-path").map(PathBuf::from);
    if source_root.is_some() != relative_path.is_some() {
        bail!("--source-root and --relative-path must be supplied together");
    }
    Ok(Some(CopyHookRequest {
        source,
        destination,
        torrent_hash: required_text(&mut values, "--torrent-hash")?,
        torrent_name: required_text(&mut values, "--torrent-name")?,
        job_id: required_text(&mut values, "--job-id")?,
        source_root,
        relative_path,
    }))
}

fn required_text(values: &mut HashMap<String, OsString>, key: &str) -> Result<String> {
    values
        .remove(key)
        .with_context(|| format!("{key} is required"))?
        .into_string()
        .map_err(|_| anyhow::anyhow!("{key} must be valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(extra: &[&str]) -> Vec<OsString> {
        [
            "--source",
            "/media/My Payload",
            "--torrent-hash",
            "abc123",
            "--torrent-name",
            "My Payload",
            "--job-id",
            "job-123",
        ]
        .into_iter()
        .chain(extra.iter().copied())
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn original_hook_arguments_keep_the_legacy_destination_and_route() {
        let request = parse_args(arguments(&[])).unwrap().unwrap();
        assert_eq!(request.source, PathBuf::from("/media/My Payload"));
        assert_eq!(request.destination, PathBuf::from(DESTINATION_ROOT));
        assert_eq!(request.torrent_name, "My Payload");
        assert_eq!(request.torrent_hash, "abc123");
        assert_eq!(request.job_id, "job-123");
        assert!(request.source_root.is_none());
        assert!(request.relative_path.is_none());
    }

    #[test]
    fn routed_options_require_both_parts_and_preserve_override() {
        assert!(parse_args(arguments(&["--source-root", "/media"])).is_err());
        let request = parse_args(arguments(&[
            "--source-root=/media",
            "--relative-path=My Payload",
            "--destination=/copy-target/media",
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(request.destination, PathBuf::from("/copy-target/media"));
        assert_eq!(request.source_root, Some(PathBuf::from("/media")));
        assert_eq!(request.relative_path, Some(PathBuf::from("My Payload")));
    }

    #[test]
    fn help_and_bad_arguments_do_not_start_a_copy() {
        assert!(parse_args([OsString::from("--help")]).unwrap().is_none());
        assert!(parse_args(Vec::<OsString>::new()).is_err());
        assert!(parse_args(arguments(&["--unknown", "value"])).is_err());
        assert!(parse_args(arguments(&["--destination"])).is_err());
    }
}
