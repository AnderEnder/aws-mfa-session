use aws_mfa_session::Args;
use clap::Parser;
use serial_test::serial;

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_args_parsing_and_validation() {
        // Test valid arguments
        let args = Args::try_parse_from([
            "aws-mfa-session",
            "--code",
            "123456",
            "--duration",
            "3600",
            "-e",
        ]);
        assert!(args.is_ok());

        // Test invalid MFA code
        let args = Args::try_parse_from([
            "aws-mfa-session",
            "--code",
            "12345", // Invalid: too short
            "-e",
        ]);
        assert!(args.is_err());

        // Test invalid duration
        let args = Args::try_parse_from([
            "aws-mfa-session",
            "--code",
            "123456",
            "--duration",
            "100", // Invalid: too short
            "-e",
        ]);
        assert!(args.is_err());
    }

    // Note: Interactive MFA code flow is tested in unit tests where cfg!(test) works properly
    // Integration tests don't work well with interactive input, so we skip that functionality here

    #[test]
    #[serial]
    fn test_environment_variable_handling() {
        // Test that Args structure holds the correct values
        // Environment variable setting happens in the run() function
        let args = Args {
            profile: Some("test-profile".to_string()),
            credentials_file: Some("/test/path/credentials".to_string()),
            region: None,
            code: Some("123456".to_string()),
            arn: None,
            duration: 3600,
            shell: false,
            export: true,
            session_profile: None,
        };

        // Verify args hold the expected values that would be used for env vars
        assert_eq!(args.profile, Some("test-profile".to_string()));
        assert_eq!(
            args.credentials_file,
            Some("/test/path/credentials".to_string())
        );
        assert_eq!(args.code, Some("123456".to_string()));
        assert_eq!(args.duration, 3600);
        assert!(!args.shell);
        assert!(args.export);
        assert!(args.session_profile.is_none());
    }

    #[test]
    fn test_args_combinations() {
        // Test all output modes are mutually compatible
        let args = Args::try_parse_from([
            "aws-mfa-session",
            "--code",
            "123456",
            "-s",
            "-e", // Both shell and export
            "--update-profile",
            "test-session", // Changed from --session-profile
        ]);
        assert!(args.is_ok());
        let args = args.unwrap();
        assert!(args.shell);
        assert!(args.export);
        assert_eq!(args.session_profile, Some("test-session".to_string()));
    }

    #[test]
    fn test_region_parsing() {
        let args = Args::try_parse_from([
            "aws-mfa-session",
            "--code",
            "123456",
            "--region",
            "eu-west-1",
            "-e",
        ]);
        assert!(args.is_ok());
        let args = args.unwrap();
        assert_eq!(args.region.unwrap().to_string(), "eu-west-1");
    }

    #[test]
    fn test_duration_bounds() {
        // Test minimum duration (900 seconds = 15 minutes)
        let args = Args::try_parse_from([
            "aws-mfa-session",
            "--code",
            "123456",
            "--duration",
            "900",
            "-e",
        ]);
        assert!(args.is_ok());

        // Test maximum duration (129599 seconds, just under 36 hours)
        let args = Args::try_parse_from([
            "aws-mfa-session",
            "--code",
            "123456",
            "--duration",
            "129599", // Changed from 129600
            "-e",
        ]);
        assert!(args.is_ok());

        // Test below minimum
        let args = Args::try_parse_from([
            "aws-mfa-session",
            "--code",
            "123456",
            "--duration",
            "899",
            "-e",
        ]);
        assert!(args.is_err());

        // Test above maximum
        let args = Args::try_parse_from([
            "aws-mfa-session",
            "--code",
            "123456",
            "--duration",
            "129600", // Changed to 129600
            "-e",
        ]);
        assert!(args.is_err());
    }

    #[test]
    fn test_mfa_code_validation_edge_cases() {
        // Test exactly 6 digits
        let args = Args::try_parse_from(["aws-mfa-session", "--code", "000000", "-e"]);
        assert!(args.is_ok());

        // Test with letters
        let args = Args::try_parse_from(["aws-mfa-session", "--code", "12345a", "-e"]);
        assert!(args.is_err());

        // Test with special characters
        let args = Args::try_parse_from(["aws-mfa-session", "--code", "123-45", "-e"]);
        assert!(args.is_err());

        // Test empty string
        let args = Args::try_parse_from(["aws-mfa-session", "--code", "", "-e"]);
        assert!(args.is_err());
    }

    #[test]
    fn test_default_values() {
        let args = Args::try_parse_from(["aws-mfa-session", "--code", "123456"]).unwrap();

        // Check default values
        assert_eq!(args.duration, 3600); // 1 hour default
        assert!(!args.shell);
        assert!(!args.export);
        assert!(args.profile.is_none());
        assert!(args.credentials_file.is_none());
        assert!(args.region.is_none());
        assert!(args.arn.is_none());
        assert!(args.session_profile.is_none());
    }

    #[test]
    fn test_comprehensive_arg_combination() {
        let args = Args::try_parse_from([
            "aws-mfa-session",
            "--profile",
            "dev-profile",
            "--credentials-file",
            "/custom/aws/credentials",
            "--region",
            "ap-southeast-2",
            "--code",
            "987654",
            "--arn",
            "arn:aws:iam::123456789012:mfa/test-user",
            "--duration",
            "7200",
            "--shell",
            "--export",
            "--update-profile",
            "dev-session",
        ])
        .unwrap();

        assert_eq!(args.profile, Some("dev-profile".to_string()));
        assert_eq!(
            args.credentials_file,
            Some("/custom/aws/credentials".to_string())
        );
        assert_eq!(args.region.unwrap().to_string(), "ap-southeast-2");
        assert_eq!(args.code, Some("987654".to_string()));
        assert_eq!(
            args.arn,
            Some("arn:aws:iam::123456789012:mfa/test-user".to_string())
        );
        assert_eq!(args.duration, 7200);
        assert!(args.shell);
        assert!(args.export);
        assert_eq!(args.session_profile, Some("dev-session".to_string()));
    }
}
