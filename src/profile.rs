//! Looks up a profile's `mfa_serial` in the shared AWS config files.

use std::fs;
use std::path::Path;

use aws_shared_config::{Document, FileKind};

/// The `mfa_serial` configured for `profile`. The config file
/// (`~/.aws/config`) takes precedence over the credentials file.
pub fn mfa_serial(
    config_file: Option<&Path>,
    credentials_file: Option<&Path>,
    profile: &str,
) -> Option<String> {
    [
        (config_file, FileKind::Config),
        (credentials_file, FileKind::Credentials),
    ]
    .into_iter()
    .find_map(|(file, kind)| mfa_serial_in(&fs::read_to_string(file?).ok()?, kind, profile))
}

/// Profiles are `[profile name]` (or `[default]`) in the config file and
/// `[name]` in the credentials file, as the AWS SDKs read them.
fn mfa_serial_in(contents: &str, kind: FileKind, profile: &str) -> Option<String> {
    let doc = Document::parse(contents, kind).ok()?;
    doc.profile(profile)?.get("mfa_serial").map(str::to_owned)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_config_file_profiles() {
        let config = "\
[default]
mfa_serial = arn:aws:iam::123456789012:mfa/default-user

[profile dev]
mfa_serial = arn:aws:iam::123456789012:mfa/dev-user # the dev account
region = us-west-2

[prod]
mfa_serial = ignored-without-profile-prefix
";
        let lookup = |profile| mfa_serial_in(config, FileKind::Config, profile);
        assert_eq!(
            lookup("default").as_deref(),
            Some("arn:aws:iam::123456789012:mfa/default-user")
        );
        assert_eq!(
            lookup("dev").as_deref(),
            Some("arn:aws:iam::123456789012:mfa/dev-user")
        );
        assert_eq!(lookup("prod"), None);
        assert_eq!(lookup("missing"), None);
    }

    #[test]
    fn test_prefixed_default_wins() {
        let config = "[default]\nmfa_serial = plain\n\n[profile default]\nmfa_serial = prefixed\n";
        assert_eq!(
            mfa_serial_in(config, FileKind::Config, "default").as_deref(),
            Some("prefixed")
        );
    }

    #[test]
    fn test_credentials_file_profiles() {
        let credentials =
            "[dev]\nmfa_serial = GAHT12345678\n\n[profile prod]\nmfa_serial = ignored\n";
        let lookup = |profile| mfa_serial_in(credentials, FileKind::Credentials, profile);
        assert_eq!(lookup("dev").as_deref(), Some("GAHT12345678"));
        assert_eq!(lookup("prod"), None);
    }

    #[test]
    fn test_missing_or_invalid_files() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        assert_eq!(mfa_serial(Some(&missing), Some(&missing), "dev"), None);
        assert_eq!(mfa_serial(None, None, "dev"), None);

        let invalid = dir.path().join("invalid");
        fs::write(&invalid, "mfa_serial = no section\n").unwrap();
        assert_eq!(mfa_serial(Some(&invalid), None, "dev"), None);
    }

    #[test]
    fn test_config_file_takes_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        let credentials = dir.path().join("credentials");
        fs::write(&config, "[profile dev]\nmfa_serial = from-config\n").unwrap();
        fs::write(&credentials, "[dev]\nmfa_serial = from-credentials\n").unwrap();

        assert_eq!(
            mfa_serial(Some(&config), Some(&credentials), "dev").as_deref(),
            Some("from-config")
        );
        assert_eq!(
            mfa_serial(None, Some(&credentials), "dev").as_deref(),
            Some("from-credentials")
        );
    }

    #[test]
    fn test_falls_back_to_credentials_file() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        let credentials = dir.path().join("credentials");
        fs::write(&config, "[profile dev]\nregion = us-west-2\n").unwrap();
        fs::write(&credentials, "[dev]\nmfa_serial = from-credentials\n").unwrap();

        assert_eq!(
            mfa_serial(Some(&config), Some(&credentials), "dev").as_deref(),
            Some("from-credentials")
        );
    }
}
