//! Looks up profile settings, such as `mfa_serial`, in the shared AWS files.

use std::fs;
use std::path::Path;

use aws_shared_config::{Document, FileKind};

/// The `key` setting of `profile`. The config file (`~/.aws/config`) takes
/// precedence over the credentials file.
pub fn setting(
    config_file: Option<&Path>,
    credentials_file: Option<&Path>,
    profile: &str,
    key: &str,
) -> Option<String> {
    [
        (config_file, FileKind::Config),
        (credentials_file, FileKind::Credentials),
    ]
    .into_iter()
    .find_map(|(file, kind)| setting_in(&fs::read_to_string(file?).ok()?, kind, profile, key))
}

/// Profiles are `[profile name]` (or `[default]`) in the config file and
/// `[name]` in the credentials file, as the AWS SDKs read them.
fn setting_in(contents: &str, kind: FileKind, profile: &str, key: &str) -> Option<String> {
    let doc = Document::parse(contents, kind).ok()?;
    doc.profile(profile)?.get(key).map(str::to_owned)
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
        let lookup = |profile| setting_in(config, FileKind::Config, profile, "mfa_serial");
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
            setting_in(config, FileKind::Config, "default", "mfa_serial").as_deref(),
            Some("prefixed")
        );
    }

    #[test]
    fn test_credentials_file_profiles() {
        let credentials =
            "[dev]\nmfa_serial = GAHT12345678\n\n[profile prod]\nmfa_serial = ignored\n";
        let lookup =
            |profile| setting_in(credentials, FileKind::Credentials, profile, "mfa_serial");
        assert_eq!(lookup("dev").as_deref(), Some("GAHT12345678"));
        assert_eq!(lookup("prod"), None);
    }

    #[test]
    fn test_missing_or_invalid_files() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        assert_eq!(
            setting(Some(&missing), Some(&missing), "dev", "mfa_serial"),
            None
        );
        assert_eq!(setting(None, None, "dev", "mfa_serial"), None);

        let invalid = dir.path().join("invalid");
        fs::write(&invalid, "mfa_serial = no section\n").unwrap();
        assert_eq!(setting(Some(&invalid), None, "dev", "mfa_serial"), None);
    }

    #[test]
    fn test_config_file_takes_precedence() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        let credentials = dir.path().join("credentials");
        fs::write(&config, "[profile dev]\nmfa_serial = from-config\n").unwrap();
        fs::write(&credentials, "[dev]\nmfa_serial = from-credentials\n").unwrap();

        assert_eq!(
            setting(Some(&config), Some(&credentials), "dev", "mfa_serial").as_deref(),
            Some("from-config")
        );
        assert_eq!(
            setting(None, Some(&credentials), "dev", "mfa_serial").as_deref(),
            Some("from-credentials")
        );
    }

    #[test]
    fn test_other_settings() {
        let config = "[profile dev]\nmfa_process = ykman oath accounts code --single aws\n";
        assert_eq!(
            setting_in(config, FileKind::Config, "dev", "mfa_process").as_deref(),
            Some("ykman oath accounts code --single aws")
        );
        assert_eq!(
            setting_in(config, FileKind::Config, "dev", "mfa_serial"),
            None
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
            setting(Some(&config), Some(&credentials), "dev", "mfa_serial").as_deref(),
            Some("from-credentials")
        );
    }
}
