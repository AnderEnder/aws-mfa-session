use dirs::home_dir;
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

/// Insert or replace `profile`'s section in an INI `config`, touching only the
/// target section. Everything else — comments, ordering, spacing of other
/// sections — is preserved byte-for-byte.
///
/// Section detection is line-based: a header is a line whose trimmed text starts
/// with `[`, and the target section is the header line whose trimmed text equals
/// `[name]` exactly. This avoids the substring/prefix and `$`-expansion hazards
/// of the previous regex-replacement approach.
pub fn update_profile(config: &str, profile: &Profile) -> String {
    let target = profile.config_section_header(); // "[name]"
    let new_section = profile.config_section(); // ends with a single '\n'

    // Keep line endings attached so the untouched parts are rebuilt verbatim
    // (also handles "\r\n" since trimming removes the trailing '\r').
    let lines: Vec<&str> = config.split_inclusive('\n').collect();
    let is_header = |l: &str| l.trim_start().starts_with('[');

    match lines.iter().position(|l| l.trim() == target) {
        Some(start) => {
            // Span runs to the next section header (or EOF)...
            let mut end = lines.len();
            for (i, l) in lines.iter().enumerate().skip(start + 1) {
                if is_header(l) {
                    end = i;
                    break;
                }
            }
            // ...but trailing blank lines act as separators and stay put.
            while end - 1 > start && lines[end - 1].trim().is_empty() {
                end -= 1;
            }

            let mut out = String::with_capacity(config.len() + new_section.len());
            lines[..start].iter().for_each(|l| out.push_str(l));
            out.push_str(&new_section);
            lines[end..].iter().for_each(|l| out.push_str(l));
            out
        }
        None if config.is_empty() => new_section,
        None => {
            // Append after the existing content with exactly one blank-line separator.
            let mut out = config.to_string();
            if !out.ends_with('\n') {
                out.push('\n');
            }
            if !out.ends_with("\n\n") {
                out.push('\n');
            }
            out.push_str(&new_section);
            out
        }
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

    // A missing credentials file is a valid starting point (e.g. env-var-only
    // auth, fresh setup): treat it as empty and create it below.
    let config = match fs::read_to_string(&file_path) {
        Ok(config) => config,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e),
    };
    let updated_config = update_profile(&config, profile);

    // Ensure the parent directory exists so the temp file can be created next to
    // the target (required for an atomic same-filesystem rename). Only adjust
    // permissions on a directory we create ourselves — never re-permission a
    // pre-existing directory the user owns.
    let temp_dir = file_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    if !temp_dir.as_os_str().is_empty() && !temp_dir.exists() {
        fs::create_dir_all(temp_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // We just created ~/.aws; it should not be group/other accessible.
            let _ = fs::set_permissions(temp_dir, fs::Permissions::from_mode(0o700));
        }
    }

    let temp_file = NamedTempFile::new_in(temp_dir)?;
    fs::write(temp_file.path(), updated_config)?;

    // Enforce 0600 on the secret-bearing file rather than inheriting whatever
    // permissions the original had (which may have been group/world readable).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp_file.path(), fs::Permissions::from_mode(0o600))?;
    }

    temp_file.persist(&file_path)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use serial_test::serial;

    fn sample_profile(name: &str) -> Profile {
        Profile {
            name: name.to_string(),
            access_key_id: "AKIATEST".to_string(),
            secret_access_key: "secret".to_string(),
            session_token: Some("token".to_string()),
            region: Some("us-east-1".to_string()),
        }
    }

    #[test]
    fn test_update_profile_empty() {
        let profile = Profile {
            name: String::from("session-production"),
            access_key_id: String::from("AACCCCEESSSSKKEEYY"),
            secret_access_key: String::from("SEC123RET"),
            session_token: None,
            region: None,
        };
        // An empty config yields just the section (no leading blank lines).
        let updated = update_profile("", &profile);
        assert_eq!(
            updated,
            r##"[session-production]
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

        // Appended after the existing content with a single blank-line separator.
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

        // Replacing the last section leaves a single trailing newline (no extra blank line).
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

        // Idempotent, and the last-section replace keeps a single trailing newline.
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
    #[serial]
    fn test_credential_file_default_path() {
        // Test that credential_file returns a path ending with .aws/credentials
        // when AWS_SHARED_CREDENTIALS_FILE is not set
        let file = credential_file().unwrap();
        let path_str = file.to_string_lossy();

        // Check that the path ends with .aws and credentials, accounting for different path separators
        assert!(path_str.contains(".aws"));
        assert!(path_str.ends_with("credentials"));

        // On Unix-like systems, should end with .aws/credentials
        // On Windows, should end with .aws\credentials
        #[cfg(unix)]
        assert!(path_str.ends_with(".aws/credentials"));

        #[cfg(windows)]
        assert!(path_str.ends_with(".aws\\credentials"));
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

    #[test]
    fn test_update_profile_preserves_comments() {
        let original = "\
# top comment
[default]
aws_access_key_id = DEFAULTKEY
; keep this comment between keys
aws_secret_access_key = DEFAULTSECRET

[session]
aws_access_key_id = OLD
aws_secret_access_key = OLD
";
        let updated = update_profile(original, &sample_profile("session"));
        // Untouched section (and its comments) survive byte-for-byte.
        assert!(updated.contains(
            "# top comment\n[default]\naws_access_key_id = DEFAULTKEY\n; keep this comment between keys\naws_secret_access_key = DEFAULTSECRET\n"
        ));
        // Target section was rewritten.
        assert!(updated.contains("[session]\naws_access_key_id = AKIATEST\n"));
        assert!(!updated.contains("aws_access_key_id = OLD"));
    }

    #[test]
    fn test_update_profile_prefix_names_dont_collide() {
        let original = "\
[prod]
aws_access_key_id = PRODKEY
aws_secret_access_key = PRODSECRET

[production]
aws_access_key_id = PRODUCTIONKEY
aws_secret_access_key = PRODUCTIONSECRET
";
        let updated = update_profile(original, &sample_profile("prod"));
        assert!(updated.contains("[prod]\naws_access_key_id = AKIATEST\n"));
        // [production] must be untouched even though [prod] is a prefix of it.
        assert!(updated.contains(
            "[production]\naws_access_key_id = PRODUCTIONKEY\naws_secret_access_key = PRODUCTIONSECRET\n"
        ));
        assert!(!updated.contains("PRODKEY"));
    }

    #[test]
    fn test_update_profile_comment_mentioning_section_is_not_a_header() {
        // A comment that merely mentions [session] must not be treated as the
        // section header (the old `config.contains()` check had this bug).
        let original = "\
# remember to rotate [session] keys
[default]
aws_access_key_id = DEFAULTKEY
aws_secret_access_key = DEFAULTSECRET
";
        let updated = update_profile(original, &sample_profile("session"));
        assert!(updated.contains("# remember to rotate [session] keys"));
        // The profile is appended; the only real `[session]` header is the new one.
        assert_eq!(updated.matches("[session]\n").count(), 1);
        assert!(updated.trim_end().ends_with("region = us-east-1"));
    }

    #[test]
    fn test_update_profile_dollar_is_literal_not_capture_ref() {
        // Regression: the previous `Regex::replace` expanded `$1`/`${name}` in the
        // replacement string, silently dropping characters. Values must be literal.
        let profile = Profile {
            name: "session".to_string(),
            access_key_id: "AKIATEST".to_string(),
            secret_access_key: "se$1cret".to_string(),
            session_token: Some("tok${en}".to_string()),
            region: Some("us-$0-1".to_string()),
        };
        let original = "[session]\naws_access_key_id = OLD\naws_secret_access_key = OLD\n";
        let updated = update_profile(original, &profile);
        assert!(
            updated.contains("aws_secret_access_key = se$1cret"),
            "got:\n{updated}"
        );
        assert!(updated.contains("aws_session_token = tok${en}"));
        assert!(updated.contains("region = us-$0-1"));
    }

    #[test]
    fn test_update_profile_replace_last_without_trailing_newline() {
        let original = "[default]\naws_access_key_id = D\n\n[session]\naws_access_key_id = OLD\naws_secret_access_key = OLD";
        let updated = update_profile(original, &sample_profile("session"));
        assert!(updated.contains("[default]\naws_access_key_id = D\n"));
        assert!(updated.contains("[session]\naws_access_key_id = AKIATEST\n"));
        assert!(!updated.contains("OLD"));
        assert!(updated.ends_with("region = us-east-1\n"));
    }

    #[test]
    fn test_update_profile_bracket_in_value_does_not_split_section() {
        // A `[` that is not at the start of a line is not a section boundary, so
        // the span scan must run past it to the real next header ([session]).
        let original = "[default]\naws_access_key_id = OLDKEY\nnote = see [archive] dump\naws_secret_access_key = OLDSECRET\n\n[session]\naws_access_key_id = KEEP\n";
        let updated = update_profile(original, &sample_profile("default"));
        // [default] replaced wholesale (note line gone); [session] untouched.
        assert!(!updated.contains("note = see [archive] dump"));
        assert!(!updated.contains("OLDKEY"));
        assert!(updated.contains("[default]\naws_access_key_id = AKIATEST\n"));
        assert!(updated.contains("[session]\naws_access_key_id = KEEP\n"));
    }

    #[test]
    fn test_update_profile_handles_crlf_in_untouched_sections() {
        let original =
            "[default]\r\naws_access_key_id = D\r\n\r\n[session]\r\naws_access_key_id = OLD\r\n";
        let updated = update_profile(original, &sample_profile("session"));
        // CRLF content outside the target is preserved verbatim.
        assert!(updated.contains("[default]\r\naws_access_key_id = D\r\n"));
        assert!(updated.contains("[session]\naws_access_key_id = AKIATEST\n"));
        assert!(!updated.contains("OLD"));
    }

    #[test]
    fn test_update_profile_append_then_replace_is_idempotent() {
        let base = "[default]\naws_access_key_id = D\naws_secret_access_key = S\n";
        let once = update_profile(base, &sample_profile("session"));
        let twice = update_profile(&once, &sample_profile("session"));
        assert_eq!(once, twice);
        assert!(twice.contains("[default]\naws_access_key_id = D\n"));
        assert_eq!(twice.matches("[session]\n").count(), 1);
    }

    #[test]
    #[serial]
    fn test_update_credentials_creates_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        // Parent directory does not exist yet either.
        let path = dir.path().join("nested").join("credentials");
        assert!(!path.exists());

        unsafe { std::env::set_var(AWS_SHARED_CREDENTIALS_FILE, &path) };
        let result = update_credentials(&sample_profile("session"));
        unsafe { std::env::remove_var(AWS_SHARED_CREDENTIALS_FILE) };
        result.unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("[session]"));
        assert!(written.contains("aws_access_key_id = AKIATEST"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "newly created credentials file must be 0600"
            );
        }
    }

    #[test]
    #[serial]
    fn test_update_credentials_enforces_0600_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials");
        std::fs::write(&path, "[existing]\naws_access_key_id = OLD\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        unsafe { std::env::set_var(AWS_SHARED_CREDENTIALS_FILE, &path) };
        let result = update_credentials(&sample_profile("session"));
        unsafe { std::env::remove_var(AWS_SHARED_CREDENTIALS_FILE) };
        result.unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("[existing]")); // pre-existing content preserved
        assert!(written.contains("[session]")); // new profile appended

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "loose 0644 permissions must be tightened to 0600"
            );
        }
    }

    #[test]
    #[serial]
    fn test_update_credentials_does_not_repermission_existing_dir() {
        let dir = tempfile::tempdir().unwrap();
        // The parent directory already exists with perms the tool must not change.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = dir.path().join("credentials");

        unsafe { std::env::set_var(AWS_SHARED_CREDENTIALS_FILE, &path) };
        let result = update_credentials(&sample_profile("session"));
        unsafe { std::env::remove_var(AWS_SHARED_CREDENTIALS_FILE) };
        result.unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
            assert_eq!(
                dir_mode & 0o777,
                0o755,
                "a pre-existing parent directory must be left untouched"
            );
            // The credentials file itself is still written 0600.
            let file_mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(file_mode & 0o777, 0o600);
        }
    }
}
