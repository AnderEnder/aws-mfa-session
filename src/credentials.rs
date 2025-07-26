use dirs::home_dir;
use regex::{Regex, escape};
use std::path::PathBuf;
use std::{fs, io};
use tempfile::NamedTempFile;

pub struct Profile {
    pub name: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub region: Option<String>,
}

impl Profile {
    fn config_section_header(&self) -> String {
        format!("[{}]", self.name)
    }

    pub fn config_section(&self) -> String {
        let mut result = self.config_section_header();
        result.push('\n');
        result.push_str("aws_access_key_id = ");
        result.push_str(&self.access_key_id);

        result.push('\n');
        result.push_str("aws_secret_access_key = ");
        result.push_str(&self.secret_access_key);

        if let Some(ref session_token) = self.session_token {
            result.push('\n');
            result.push_str("aws_session_token = ");
            result.push_str(session_token);
        }
        if let Some(ref region) = self.region {
            result.push('\n');
            result.push_str("region = ");
            result.push_str(region);
        }

        result.push('\n');
        result
    }
}

pub fn update_profile(config: &str, profile: &Profile) -> String {
    let header = profile.config_section_header();
    let mut section = profile.config_section();
    if config.contains(&header) {
        section.push('\n');

        // replace
        let expr = format!("{}[^\\[]+", escape(&header));
        let regex = Regex::new(&expr).unwrap();
        regex.replace(config, section.as_str()).to_string()
    } else {
        // append
        format!("{}\n\n{}", config, profile.config_section())
    }
}

pub const AWS_SHARED_CREDENTIALS_FILE: &str = "AWS_SHARED_CREDENTIALS_FILE";

// Get credentials file from environment variable or use system default
// https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html
// Linux or macOS: ~/.aws/credentials
// Windows: "%UserProfile%\.aws\credentials"
fn credential_file() -> io::Result<PathBuf> {
    let file = match std::env::var(AWS_SHARED_CREDENTIALS_FILE) {
        Ok(s) => PathBuf::from(s),
        _ => {
            let mut file =
                home_dir().ok_or_else(|| io::Error::other("Cannot find home directory"))?;
            file.push(".aws");
            file.push("credentials");
            file
        }
    };
    Ok(file)
}

pub fn update_credentials(profile: &Profile) -> io::Result<()> {
    let file_path = credential_file()?;
    let config = fs::read_to_string(&file_path)?;
    let updated_config = update_profile(&config, profile);

    let original_metadata = fs::metadata(&file_path)?;
    let original_permissions = original_metadata.permissions();

    let temp_dir = file_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let temp_file = NamedTempFile::new_in(temp_dir)?;

    fs::write(temp_file.path(), updated_config)?;
    fs::set_permissions(temp_file.path(), original_permissions)?;

    temp_file.persist(&file_path)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_update_profile_empty() {
        let profile = Profile {
            name: String::from("session-production"),
            access_key_id: String::from("AACCCCEESSSSKKEEYY"),
            secret_access_key: String::from("SEC123RET"),
            session_token: None,
            region: None,
        };
        let updated = update_profile("", &profile);
        assert_eq!(
            updated,
            r##"

[session-production]
aws_access_key_id = AACCCCEESSSSKKEEYY
aws_secret_access_key = SEC123RET
"##
        )
    }

    #[test]
    fn test_update_profile_append() {
        let profile = Profile {
            name: String::from("session-production"),
            access_key_id: String::from("AACCCCEESSSSKKEEYY"),
            secret_access_key: String::from("SEC123RET"),
            session_token: None,
            region: None,
        };

        let original = r##"[default]
aws_access_key_id = AACCCCEESSSSKKEEYY/DEFAULT
aws_secret_access_key = SEC123RET/DEFAULT

[production]
aws_access_key_id = AACCCCEESSSSKKEEYY/PROD
aws_secret_access_key = SEC123RET/PROD
"##;

        let updated = update_profile(original, &profile);
        assert_eq!(
            updated,
            r##"[default]
aws_access_key_id = AACCCCEESSSSKKEEYY/DEFAULT
aws_secret_access_key = SEC123RET/DEFAULT

[production]
aws_access_key_id = AACCCCEESSSSKKEEYY/PROD
aws_secret_access_key = SEC123RET/PROD


[session-production]
aws_access_key_id = AACCCCEESSSSKKEEYY
aws_secret_access_key = SEC123RET
"##
        )
    }

    #[test]
    fn test_update_profile_replace_first() {
        let profile = Profile {
            name: String::from("session-production"),
            access_key_id: String::from("AACCCCEESSSSKKEEYY/NEW"),
            secret_access_key: String::from("SEC123RET/NEW"),
            session_token: None,
            region: None,
        };

        let original = r##"[session-production]
aws_access_key_id = AACCCCEESSSSKKEEYY/OLD
aws_secret_access_key = SEC123RET/OLD

[default]
aws_access_key_id = AACCCCEESSSSKKEEYY/DEFAULT
aws_secret_access_key = SEC123RET/DEFAULT

[production]
aws_access_key_id = AACCCCEESSSSKKEEYY/PROD
aws_secret_access_key = SEC123RET/PROD"##;

        let updated = update_profile(original, &profile);
        assert_eq!(
            updated,
            r##"[session-production]
aws_access_key_id = AACCCCEESSSSKKEEYY/NEW
aws_secret_access_key = SEC123RET/NEW

[default]
aws_access_key_id = AACCCCEESSSSKKEEYY/DEFAULT
aws_secret_access_key = SEC123RET/DEFAULT

[production]
aws_access_key_id = AACCCCEESSSSKKEEYY/PROD
aws_secret_access_key = SEC123RET/PROD"##
        );
    }

    #[test]
    fn test_update_profile_replace_inside() {
        let profile = Profile {
            name: String::from("session-production"),
            access_key_id: String::from("AACCCCEESSSSKKEEYY/NEW"),
            secret_access_key: String::from("SEC123RET/NEW"),
            session_token: None,
            region: None,
        };

        let original = r##"[default]
aws_access_key_id = AACCCCEESSSSKKEEYY/DEFAULT
aws_secret_access_key = SEC123RET/DEFAULT

[session-production]
aws_access_key_id = AACCCCEESSSSKKEEYY/OLD
aws_secret_access_key = SEC123RET/OLD

[production]
aws_access_key_id = AACCCCEESSSSKKEEYY/PROD
aws_secret_access_key = SEC123RET/PROD"##;

        let updated = update_profile(original, &profile);
        assert_eq!(
            updated,
            r##"[default]
aws_access_key_id = AACCCCEESSSSKKEEYY/DEFAULT
aws_secret_access_key = SEC123RET/DEFAULT

[session-production]
aws_access_key_id = AACCCCEESSSSKKEEYY/NEW
aws_secret_access_key = SEC123RET/NEW

[production]
aws_access_key_id = AACCCCEESSSSKKEEYY/PROD
aws_secret_access_key = SEC123RET/PROD"##
        );
    }

    #[test]
    fn test_update_profile_replace_last() {
        let profile = Profile {
            name: String::from("session-production"),
            access_key_id: String::from("AACCCCEESSSSKKEEYY/NEW"),
            secret_access_key: String::from("SEC123RET/NEW"),
            session_token: None,
            region: None,
        };

        let original = r##"[default]
aws_access_key_id = AACCCCEESSSSKKEEYY/DEFAULT
aws_secret_access_key = SEC123RET/DEFAULT

[production]
aws_access_key_id = AACCCCEESSSSKKEEYY/PROD
aws_secret_access_key = SEC123RET/PROD

[session-production]
aws_access_key_id = AACCCCEESSSSKKEEYY/OLD
aws_secret_access_key = SEC123RET/OLD"##;

        let updated = update_profile(original, &profile);
        assert_eq!(
            updated,
            r##"[default]
aws_access_key_id = AACCCCEESSSSKKEEYY/DEFAULT
aws_secret_access_key = SEC123RET/DEFAULT

[production]
aws_access_key_id = AACCCCEESSSSKKEEYY/PROD
aws_secret_access_key = SEC123RET/PROD

[session-production]
aws_access_key_id = AACCCCEESSSSKKEEYY/NEW
aws_secret_access_key = SEC123RET/NEW

"##
        );
    }

    #[test]
    fn test_update_profile_replace_inside_double() {
        let profile = Profile {
            name: String::from("session-production"),
            access_key_id: String::from("AACCCCEESSSSKKEEYY/NEW"),
            secret_access_key: String::from("SEC123RET/NEW"),
            session_token: None,
            region: None,
        };

        let original = r##"[default]
aws_access_key_id = AACCCCEESSSSKKEEYY/DEFAULT
aws_secret_access_key = SEC123RET/DEFAULT

[session-production]
aws_access_key_id = AACCCCEESSSSKKEEYY/OLD
aws_secret_access_key = SEC123RET/OLD

[production]
aws_access_key_id = AACCCCEESSSSKKEEYY/PROD
aws_secret_access_key = SEC123RET/PROD"##;

        let updated_first = update_profile(original, &profile);
        let updated = update_profile(&updated_first, &profile);
        assert_eq!(
            updated,
            r##"[default]
aws_access_key_id = AACCCCEESSSSKKEEYY/DEFAULT
aws_secret_access_key = SEC123RET/DEFAULT

[session-production]
aws_access_key_id = AACCCCEESSSSKKEEYY/NEW
aws_secret_access_key = SEC123RET/NEW

[production]
aws_access_key_id = AACCCCEESSSSKKEEYY/PROD
aws_secret_access_key = SEC123RET/PROD"##
        );
    }

    #[test]
    fn test_update_profile_replace_last_double() {
        let profile = Profile {
            name: String::from("session-production"),
            access_key_id: String::from("AACCCCEESSSSKKEEYY/NEW"),
            secret_access_key: String::from("SEC123RET/NEW"),
            session_token: None,
            region: None,
        };

        let original = r##"[default]
aws_access_key_id = AACCCCEESSSSKKEEYY/DEFAULT
aws_secret_access_key = SEC123RET/DEFAULT

[production]
aws_access_key_id = AACCCCEESSSSKKEEYY/PROD
aws_secret_access_key = SEC123RET/PROD

[session-production]
aws_access_key_id = AACCCCEESSSSKKEEYY/OLD
aws_secret_access_key = SEC123RET/OLD"##;

        let updated_first = update_profile(original, &profile);
        let updated = update_profile(&updated_first, &profile);
        assert_eq!(
            updated,
            r##"[default]
aws_access_key_id = AACCCCEESSSSKKEEYY/DEFAULT
aws_secret_access_key = SEC123RET/DEFAULT

[production]
aws_access_key_id = AACCCCEESSSSKKEEYY/PROD
aws_secret_access_key = SEC123RET/PROD

[session-production]
aws_access_key_id = AACCCCEESSSSKKEEYY/NEW
aws_secret_access_key = SEC123RET/NEW

"##
        );
    }

    #[test]
    fn test_profile_with_session_token() {
        let profile = Profile {
            name: String::from("test-session"),
            access_key_id: String::from("AKIATEST"),
            secret_access_key: String::from("secret123"),
            session_token: Some(String::from("token456")),
            region: Some(String::from("us-west-2")),
        };

        let config_section = profile.config_section();
        assert!(config_section.contains("aws_access_key_id = AKIATEST"));
        assert!(config_section.contains("aws_secret_access_key = secret123"));
        assert!(config_section.contains("aws_session_token = token456"));
        assert!(config_section.contains("region = us-west-2"));
    }

    #[test]
    fn test_profile_without_optional_fields() {
        let profile = Profile {
            name: String::from("minimal-profile"),
            access_key_id: String::from("AKIATEST"),
            secret_access_key: String::from("secret123"),
            session_token: None,
            region: None,
        };

        let config_section = profile.config_section();
        assert!(config_section.contains("aws_access_key_id = AKIATEST"));
        assert!(config_section.contains("aws_secret_access_key = secret123"));
        assert!(!config_section.contains("aws_session_token"));
        assert!(!config_section.contains("region"));
    }

    #[test]
    fn test_update_profile_with_special_characters() {
        let profile = Profile {
            name: String::from("special-chars"),
            access_key_id: String::from("AKIA/TEST+KEY="),
            secret_access_key: String::from("secret/with+special=chars"),
            session_token: Some(String::from("token/with+special=chars")),
            region: Some(String::from("us-east-1")),
        };

        let updated = update_profile("", &profile);
        assert!(updated.contains("AKIA/TEST+KEY="));
        assert!(updated.contains("secret/with+special=chars"));
        assert!(updated.contains("token/with+special=chars"));
    }

    #[test]
    fn test_update_profile_empty_values() {
        let profile = Profile {
            name: String::from("empty-test"),
            access_key_id: String::from(""),
            secret_access_key: String::from(""),
            session_token: Some(String::from("")),
            region: Some(String::from("")),
        };

        let updated = update_profile("", &profile);
        assert!(updated.contains("[empty-test]"));
        assert!(updated.contains("aws_access_key_id = "));
        assert!(updated.contains("aws_secret_access_key = "));
        assert!(updated.contains("aws_session_token = "));
        assert!(updated.contains("region = "));
    }

    #[test]
    fn test_credential_file_env_var() {
        use crate::test_utils::env_mock::with_env;

        with_env(
            |env| {
                env.set("AWS_SHARED_CREDENTIALS_FILE", "/custom/path/credentials");
            },
            |_env| {
                let file = credential_file().unwrap();
                assert_eq!(file.to_str().unwrap(), "/custom/path/credentials");
            },
        );
    }

    #[test]
    fn test_credential_file_no_env_var() {
        use crate::test_utils::env_mock::with_env;

        with_env(
            |env| {
                env.remove("AWS_SHARED_CREDENTIALS_FILE");
            },
            |_env| {
                let file = credential_file().unwrap();
                // Should default to ~/.aws/credentials
                assert!(file.to_string_lossy().ends_with(".aws/credentials"));
            },
        );
    }

    #[test]
    fn test_config_section_header() {
        let profile = Profile {
            name: String::from("test-profile"),
            access_key_id: String::from("key"),
            secret_access_key: String::from("secret"),
            session_token: None,
            region: None,
        };

        assert_eq!(profile.config_section_header(), "[test-profile]");
    }
}
