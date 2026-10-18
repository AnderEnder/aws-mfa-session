//! Looks up a profile's `mfa_serial` in the shared AWS config files.

use std::path::Path;

use ini::Ini;

/// The `mfa_serial` configured for `profile`. The config file
/// (`~/.aws/config`) takes precedence over the credentials file.
pub fn mfa_serial(
    config_file: Option<&Path>,
    credentials_file: Option<&Path>,
    profile: &str,
) -> Option<String> {
    [config_file, credentials_file]
        .into_iter()
        .flatten()
        .find_map(|file| mfa_serial_in(&Ini::load_from_file(file).ok()?, profile))
}

/// Profiles are `[profile name]` in the config file and `[name]` in the
/// credentials file; both forms are accepted in either file.
fn mfa_serial_in(ini: &Ini, profile: &str) -> Option<String> {
    [format!("profile {profile}"), profile.to_owned()]
        .iter()
        .find_map(|section| ini.get_from(Some(section.as_str()), "mfa_serial"))
        .map(str::to_owned)
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs;

    fn ini(content: &str) -> Ini {
        Ini::load_from_str(content).unwrap()
    }

    #[test]
    fn test_mfa_serial_in_both_section_styles() {
        let ini = ini(r#"
[profile dev]
mfa_serial = arn:aws:iam::123456789012:mfa/dev-user
region = us-west-2

[prod]
mfa_serial = GAHT12345678
"#);
        assert_eq!(
            mfa_serial_in(&ini, "dev"),
            Some("arn:aws:iam::123456789012:mfa/dev-user".to_owned())
        );
        assert_eq!(mfa_serial_in(&ini, "prod"), Some("GAHT12345678".to_owned()));
    }

    #[test]
    fn test_mfa_serial_in_default_profile() {
        let plain = ini("[default]\nmfa_serial = arn:aws:iam::1:mfa/plain\n");
        assert_eq!(
            mfa_serial_in(&plain, "default"),
            Some("arn:aws:iam::1:mfa/plain".to_owned())
        );
        let prefixed = ini("[profile default]\nmfa_serial = arn:aws:iam::1:mfa/prefixed\n");
        assert_eq!(
            mfa_serial_in(&prefixed, "default"),
            Some("arn:aws:iam::1:mfa/prefixed".to_owned())
        );
    }

    #[test]
    fn test_mfa_serial_in_absent() {
        let ini = ini("[profile dev]\nregion = us-west-2\n\n[prod]\nregion = us-east-1\n");
        assert_eq!(mfa_serial_in(&ini, "dev"), None);
        assert_eq!(mfa_serial_in(&ini, "prod"), None);
        assert_eq!(mfa_serial_in(&ini, "missing"), None);
    }

    #[test]
    fn test_mfa_serial_prefers_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        let credentials = dir.path().join("credentials");
        fs::write(&config, "[profile dev]\nmfa_serial = from-config\n").unwrap();
        fs::write(&credentials, "[dev]\nmfa_serial = from-credentials\n").unwrap();

        assert_eq!(
            mfa_serial(Some(&config), Some(&credentials), "dev"),
            Some("from-config".to_owned())
        );
        assert_eq!(
            mfa_serial(None, Some(&credentials), "dev"),
            Some("from-credentials".to_owned())
        );
    }

    #[test]
    fn test_mfa_serial_falls_back_to_credentials_file() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        let credentials = dir.path().join("credentials");
        fs::write(&config, "[profile dev]\nregion = us-west-2\n").unwrap();
        fs::write(&credentials, "[dev]\nmfa_serial = from-credentials\n").unwrap();

        assert_eq!(
            mfa_serial(Some(&config), Some(&credentials), "dev"),
            Some("from-credentials".to_owned())
        );
    }

    #[test]
    fn test_mfa_serial_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        assert_eq!(mfa_serial(Some(&missing), Some(&missing), "dev"), None);
        assert_eq!(mfa_serial(None, None, "dev"), None);
    }
}
