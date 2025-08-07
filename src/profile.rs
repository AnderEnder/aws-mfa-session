use ini::Ini;

/// Read MFA serial from AWS profile configuration using INI parsing
pub fn get_mfa_serial_from_profile(profile_name: Option<&str>) -> Option<String> {
    let profile_name = profile_name.unwrap_or("default");

    // Use the same environment variable logic as AWS SDK for file paths
    let config_path = match std::env::var("AWS_CONFIG_FILE") {
        Ok(path) => path,
        Err(_) => {
            let mut home = dirs::home_dir()?;
            home.push(".aws");
            home.push("config");
            home.to_string_lossy().to_string()
        }
    };

    let credentials_path = match std::env::var("AWS_SHARED_CREDENTIALS_FILE") {
        Ok(path) => path,
        Err(_) => {
            let mut home = dirs::home_dir()?;
            home.push(".aws");
            home.push("credentials");
            home.to_string_lossy().to_string()
        }
    };

    // Try to read mfa_serial from both files, with config taking precedence
    let mut mfa_serial = None;

    // Check credentials file first (lower precedence)
    if std::path::Path::new(&credentials_path).exists()
        && let Some(mfa) = extract_mfa_serial_with_ini(&credentials_path, profile_name)
    {
        mfa_serial = Some(mfa);
    }

    // Check config file second (higher precedence, will override credentials file)
    if std::path::Path::new(&config_path).exists()
        && let Some(mfa) = extract_mfa_serial_with_ini(&config_path, profile_name)
    {
        mfa_serial = Some(mfa);
    }

    mfa_serial
}

/// Extract MFA serial from AWS config file using proper INI parsing
fn extract_mfa_serial_with_ini(file_path: &str, target_profile: &str) -> Option<String> {
    let conf = Ini::load_from_file(file_path).ok()?;

    // Try both AWS config file formats:
    // 1. [profile name] format (used in config files)
    // 2. [name] format (used in credentials files)

    // First try the config file format [profile name]
    let profile_section_name = if target_profile == "default" {
        // In config files, default profile can be either [default] or [profile default]
        vec!["default".to_string(), format!("profile {}", target_profile)]
    } else {
        vec![format!("profile {}", target_profile)]
    };

    for section_name in &profile_section_name {
        if let Some(section) = conf.section(Some(section_name))
            && let Some(mfa_serial) = section.get("mfa_serial")
        {
            return Some(mfa_serial.to_string());
        }
    }

    // If not found, try the credentials file format [name]
    if let Some(section) = conf.section(Some(target_profile))
        && let Some(mfa_serial) = section.get("mfa_serial")
    {
        return Some(mfa_serial.to_string());
    }

    None
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_get_mfa_serial_missing_files() {
        // Test when config files don't exist - should return None
        let mfa_serial = get_mfa_serial_from_profile(Some("nonexistent"));
        assert_eq!(mfa_serial, None);
    }

    #[test]
    fn test_extract_mfa_serial_with_ini_basic() {
        // Create a temporary file with INI content for testing
        let content = r#"
[profile dev]
mfa_serial = arn:aws:iam::123456789012:mfa/dev-user
region = us-west-2

[prod]
mfa_serial = GAHT12345678
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(content.as_bytes()).unwrap();
        let temp_path = temp_file.path().to_str().unwrap();

        let dev_mfa = extract_mfa_serial_with_ini(temp_path, "dev");
        let prod_mfa = extract_mfa_serial_with_ini(temp_path, "prod");

        assert_eq!(
            dev_mfa,
            Some("arn:aws:iam::123456789012:mfa/dev-user".to_string())
        );
        assert_eq!(prod_mfa, Some("GAHT12345678".to_string()));
    }

    #[test]
    fn test_extract_mfa_serial_with_ini_none() {
        // Create a temporary file with INI content that does NOT contain mfa_serial for the target profile
        let content = r#"
[profile dev]
region = us-west-2

[prod]
region = us-east-1
"#;
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(content.as_bytes()).unwrap();
        let temp_path = temp_file.path().to_str().unwrap();

        // Should return None for missing mfa_serial
        let dev_mfa = extract_mfa_serial_with_ini(temp_path, "dev");
        let prod_mfa = extract_mfa_serial_with_ini(temp_path, "prod");
        assert_eq!(dev_mfa, None);
        assert_eq!(prod_mfa, None);
    }
}
