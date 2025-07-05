use crate::error::CliError;
use aws_config::Region;
use clap::Parser;
use dialoguer::Input;

pub fn region(s: &str) -> Result<Region, CliError> {
    Ok(Region::new(s.to_owned()))
}

fn parse_code(s: &str) -> Result<String, CliError> {
    if s.chars().all(char::is_numeric) && s.len() == 6 {
        Ok(s.to_string())
    } else {
        Err(CliError::ValidationError(
            "MFA code must be exactly 6 digits".to_string(),
        ))
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "aws-mfa-session",
    about = "AWS MFA session manager",
    long_about = None,
)]
pub struct Args {
    /// AWS credential profile to use. AWS_PROFILE is used by default
    #[arg(long = "profile", short = 'p')]
    pub profile: Option<String>,
    /// AWS credentials file location to use. AWS_SHARED_CREDENTIALS_FILE is used if not defined
    #[arg(long = "credentials-file", short = 'f')]
    pub credentials_file: Option<String>,
    /// AWS region. AWS_REGION is used if not defined
    #[arg(long = "region", short = 'r', value_parser = region)]
    pub region: Option<Region>,
    /// MFA code from MFA resource
    #[arg(long = "code", short = 'c', value_parser = parse_code)]
    pub code: Option<String>,
    /// MFA device ARN from user profile. It could be detected automatically
    #[arg(long = "arn", short = 'a')]
    pub arn: Option<String>,
    /// Session duration in seconds (900-129600)
    #[arg(long = "duration", short = 'd', default_value_t = 3600, value_parser = clap::value_parser!(i32).range(900..129600))]
    pub duration: i32,
    /// Run shell with AWS credentials as environment variables
    #[arg(short = 's')]
    pub shell: bool,
    /// Print(export) AWS credentials as environment variables
    #[arg(short = 'e')]
    pub export: bool,
    /// Update AWS credential profile with temporary session credentials
    #[arg(long = "update-profile", short = 'u')]
    pub session_profile: Option<String>,
}

impl Args {
    pub fn get_code(&mut self) -> Result<(), CliError> {
        self.code = match &self.code {
            None => {
                if cfg!(test) {
                    Some("123456".to_string())
                } else {
                    Some(ask_code_interactive()?)
                }
            }
            code => code.to_owned(),
        };
        Ok(())
    }
}

fn ask_code_interactive() -> Result<String, CliError> {
    let code: String = Input::new()
        .with_prompt("Enter MFA code")
        .interact_text()
        .map_err(|e| CliError::ValidationError(e.to_string()))?;

    parse_code(&code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_parse_code_valid() {
        assert_eq!(parse_code("123456").unwrap(), "123456");
        assert_eq!(parse_code("000000").unwrap(), "000000");
        assert_eq!(parse_code("999999").unwrap(), "999999");
    }

    #[test]
    fn test_parse_code_invalid_length() {
        assert!(parse_code("12345").is_err());
        assert!(parse_code("1234567").is_err());
        assert!(parse_code("").is_err());
    }

    #[test]
    fn test_parse_code_invalid_characters() {
        assert!(parse_code("12345a").is_err());
        assert!(parse_code("abcdef").is_err());
        assert!(parse_code("12-456").is_err());
        assert!(parse_code("123 56").is_err());
    }

    #[test]
    fn test_region_parsing() {
        let parsed_region = region("us-east-1").unwrap();
        assert_eq!(parsed_region.to_string(), "us-east-1");

        let parsed_region = region("eu-west-1").unwrap();
        assert_eq!(parsed_region.to_string(), "eu-west-1");
    }

    #[test]
    fn test_args_parsing_minimal() {
        let args = Args::try_parse_from(["aws-mfa-session", "--code", "123456"]);
        assert!(args.is_ok());
        let args = args.unwrap();
        assert_eq!(args.code, Some("123456".to_string()));
        assert_eq!(args.duration, 3600); // default
        assert!(!args.shell);
        assert!(!args.export);
    }

    #[test]
    fn test_args_parsing_all_options() {
        let args = Args::try_parse_from([
            "aws-mfa-session",
            "--profile",
            "test-profile",
            "--credentials-file",
            "/custom/path/credentials",
            "--region",
            "us-west-2",
            "--code",
            "654321",
            "--arn",
            "arn:aws:iam::123456789012:mfa/test-user",
            "--duration",
            "7200",
            "-s",
            "-e",
            "--update-profile",
            "temp-session",
        ]);

        assert!(args.is_ok());
        let args = args.unwrap();
        assert_eq!(args.profile, Some("test-profile".to_string()));
        assert_eq!(
            args.credentials_file,
            Some("/custom/path/credentials".to_string())
        );
        assert_eq!(args.region.unwrap().to_string(), "us-west-2");
        assert_eq!(args.code, Some("654321".to_string()));
        assert_eq!(
            args.arn,
            Some("arn:aws:iam::123456789012:mfa/test-user".to_string())
        );
        assert_eq!(args.duration, 7200);
        assert!(args.shell);
        assert!(args.export);
        assert_eq!(args.session_profile, Some("temp-session".to_string()));
    }

    #[test]
    fn test_args_parsing_invalid_code() {
        let args = Args::try_parse_from(["aws-mfa-session", "--code", "12345"]);
        assert!(args.is_err());

        let args = Args::try_parse_from(["aws-mfa-session", "--code", "abcdef"]);
        assert!(args.is_err());
    }

    #[test]
    fn test_args_parsing_invalid_duration() {
        let args_low =
            Args::try_parse_from(["aws-mfa-session", "--code", "123456", "--duration", "800"]);
        assert!(args_low.is_err());

        let args_high = Args::try_parse_from([
            "aws-mfa-session",
            "--code",
            "123456",
            "--duration",
            "200000",
        ]);
        assert!(args_high.is_err());
    }

    #[test]
    fn test_args_parsing_missing_code() {
        let args = Args::try_parse_from(["aws-mfa-session"]);
        // This should succeed, as code is optional in the Args struct
        assert!(args.is_ok());
    }

    #[test]
    fn test_args_short_flags() {
        let args = Args::try_parse_from([
            "aws-mfa-session",
            "-p",
            "profile",
            "-f",
            "/path/to/file",
            "-r",
            "ap-southeast-1",
            "-c",
            "123456",
            "-a",
            "arn:aws:iam::123:mfa/user",
            "-d",
            "1800",
            "-s",
            "-e",
            "-u",
            "session",
        ]);

        assert!(args.is_ok());
        let args = args.unwrap();
        assert_eq!(args.profile, Some("profile".to_string()));
        assert_eq!(args.credentials_file, Some("/path/to/file".to_string()));
        assert_eq!(args.region.unwrap().to_string(), "ap-southeast-1");
        assert_eq!(args.code, Some("123456".to_string()));
        assert_eq!(args.arn, Some("arn:aws:iam::123:mfa/user".to_string()));
        assert_eq!(args.duration, 1800);
        assert!(args.shell);
        assert!(args.export);
        assert_eq!(args.session_profile, Some("session".to_string()));
    }

    #[test]
    fn test_command_structure() {
        let cmd = Args::command();
        assert_eq!(cmd.get_name(), "aws-mfa-session");
        assert!(cmd.get_about().is_some());
    }

    #[test]
    fn test_args_clone() {
        let args = Args::try_parse_from(["aws-mfa-session", "--code", "123456"]).unwrap();
        let cloned = args.clone();
        assert_eq!(args.code, cloned.code);
        assert_eq!(args.duration, cloned.duration);
    }

    #[test]
    fn test_args_debug() {
        let args = Args::try_parse_from(["aws-mfa-session", "--code", "123456"]).unwrap();
        let debug_str = format!("{args:?}");
        assert!(debug_str.contains("Args"));
        assert!(debug_str.contains("123456"));
    }

    #[test]
    fn test_get_code_with_existing_code() {
        let mut args = Args::try_parse_from(["aws-mfa-session", "--code", "654321"]).unwrap();
        assert_eq!(args.code, Some("654321".to_string()));

        // get_code should not change existing code
        args.get_code().unwrap();
        assert_eq!(args.code, Some("654321".to_string()));
    }

    #[test]
    fn test_get_code_without_code_in_test_mode() {
        let mut args = Args::try_parse_from(["aws-mfa-session"]).unwrap();
        assert_eq!(args.code, None);

        // In test mode, get_code should set code to "123456"
        args.get_code().unwrap();
        assert_eq!(args.code, Some("123456".to_string()));
    }

    #[test]
    fn test_get_code_preserves_existing_valid_code() {
        let mut args = Args::try_parse_from(["aws-mfa-session", "--code", "999888"]).unwrap();
        let original_code = args.code.clone();

        args.get_code().unwrap();
        assert_eq!(args.code, original_code);
    }

    #[test]
    fn test_ask_code_interactive_validation() {
        // Test that the interactive code asking validates input
        assert!(parse_code("123456").is_ok());
        assert!(parse_code("abcdef").is_err());
        assert!(parse_code("12345").is_err());
        assert!(parse_code("1234567").is_err());
    }
}
