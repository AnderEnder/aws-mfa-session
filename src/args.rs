//! Command-line interface.

use clap::builder::PossibleValue;
use clap::{ArgGroup, Parser, ValueEnum};

use crate::export::ExportFormat;
use crate::mfa::MfaCode;
use crate::shell::Shell;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "aws-mfa-session",
    version,
    about = "AWS MFA session manager",
    long_about = None,
    // Without an output mode the session would be minted — spending the MFA
    // code — and then discarded.
    group(
        ArgGroup::new("output")
            .required(true)
            .multiple(true)
            .args(["shell", "export", "session_profile"])
    ),
    // The outputs that receive the role's credentials with --role.
    group(ArgGroup::new("role_output").multiple(true).args(["shell", "export"])),
)]
pub struct Args {
    /// AWS credential profile to use. AWS_PROFILE is used by default
    #[arg(long, short = 'p')]
    pub profile: Option<String>,
    /// AWS credentials file location to use. AWS_SHARED_CREDENTIALS_FILE is used if not defined
    #[arg(long, short = 'f')]
    pub credentials_file: Option<String>,
    /// AWS region. AWS_REGION is used if not defined
    #[arg(long, short = 'r')]
    pub region: Option<String>,
    /// MFA code from MFA resource. If not provided, it comes from --mfa-process or the profile's mfa_process, or is prompted for
    #[arg(long, short = 'c')]
    pub code: Option<MfaCode>,
    /// Command that prints the MFA code, e.g. `ykman oath accounts code --single aws`. Runs through `sh -c` (`cmd /C` on Windows). The profile's mfa_process is used if not defined
    #[arg(long, value_name = "COMMAND", conflicts_with = "code")]
    pub mfa_process: Option<String>,
    /// MFA device ARN. If not provided, will try to read mfa_serial from AWS profile configuration, then fall back to automatic detection
    #[arg(long, short = 'a')]
    pub arn: Option<String>,
    /// Session duration in seconds (900-129600)
    #[arg(long, short = 'd', default_value_t = 3600, value_parser = clap::value_parser!(i32).range(900..=129600))]
    pub duration: i32,
    /// Run shell with AWS credentials as environment variables
    #[arg(long, short = 's')]
    pub shell: bool,
    /// Print(export) AWS credentials as environment variables
    #[arg(long, short = 'e')]
    pub export: bool,
    /// Output format for --export. Detected from SHELL if not defined
    #[arg(long, requires = "export")]
    pub format: Option<ExportFormat>,
    /// Update AWS credential profile with temporary session credentials. A profile that is still valid is reused
    #[arg(long = "update-profile", short = 'u', value_parser = profile_name)]
    pub session_profile: Option<String>,
    /// Request new credentials even if the --update-profile profile is still valid
    #[arg(long, requires = "session_profile")]
    pub force: bool,
    /// Assume this role with the MFA session, and pass its credentials to --export and --shell: a role ARN, or a profile with role_arn. --update-profile keeps the MFA session
    #[arg(long, value_name = "PROFILE|ARN", requires = "role_output")]
    pub role: Option<String>,
}

/// AWS tools ignore profiles whose names use other characters, so reject them
/// before the MFA code is spent on a session that could not be saved.
fn profile_name(name: &str) -> Result<String, &'static str> {
    if !name.is_empty() && aws_shared_config::is_valid_identifier(name) {
        Ok(name.to_owned())
    } else {
        Err("profile names may only use ASCII letters, digits and _-/.%@:+")
    }
}

impl ValueEnum for ExportFormat {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            ExportFormat::Shell(Shell::Bash),
            ExportFormat::Shell(Shell::Zsh),
            ExportFormat::Shell(Shell::Sh),
            ExportFormat::Shell(Shell::Fish),
            ExportFormat::Shell(Shell::Cmd),
            ExportFormat::Shell(Shell::PowerShell),
            ExportFormat::Json,
        ]
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        Some(match self {
            ExportFormat::Shell(Shell::PowerShell) => {
                PossibleValue::new("powershell").alias("pwsh")
            }
            ExportFormat::Shell(shell) => PossibleValue::new(shell.name()),
            ExportFormat::Json => PossibleValue::new("json"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use clap::error::ErrorKind;

    fn parse(args: &[&str]) -> Result<Args, clap::Error> {
        Args::try_parse_from(std::iter::once("aws-mfa-session").chain(args.iter().copied()))
    }

    #[test]
    fn test_command_is_well_formed() {
        Args::command().debug_assert();
    }

    #[test]
    fn test_defaults() {
        let args = parse(&["-e"]).unwrap();
        assert_eq!(args.duration, 3600);
        assert!(args.export);
        assert!(!args.shell);
        assert!(!args.force);
        assert_eq!(args.code, None);
        assert_eq!(args.mfa_process, None);
        assert_eq!(args.format, None);
        assert!(args.profile.is_none());
        assert!(args.credentials_file.is_none());
        assert!(args.region.is_none());
        assert!(args.arn.is_none());
        assert!(args.session_profile.is_none());
        assert!(args.role.is_none());
    }

    #[test]
    fn test_all_long_options() {
        let args = parse(&[
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
            "--shell",
            "--export",
            "--format",
            "fish",
            "--update-profile",
            "temp-session",
            "--force",
        ])
        .unwrap();

        assert_eq!(args.profile.as_deref(), Some("test-profile"));
        assert_eq!(
            args.credentials_file.as_deref(),
            Some("/custom/path/credentials")
        );
        assert_eq!(args.region.as_deref(), Some("us-west-2"));
        assert_eq!(args.code.unwrap().as_str(), "654321");
        assert_eq!(
            args.arn.as_deref(),
            Some("arn:aws:iam::123456789012:mfa/test-user")
        );
        assert_eq!(args.duration, 7200);
        assert!(args.shell);
        assert!(args.export);
        assert_eq!(args.format, Some(ExportFormat::Shell(Shell::Fish)));
        assert_eq!(args.session_profile.as_deref(), Some("temp-session"));
        assert!(args.force);
    }

    #[test]
    fn test_short_flags() {
        let args = parse(&[
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
        ])
        .unwrap();

        assert_eq!(args.profile.as_deref(), Some("profile"));
        assert_eq!(args.credentials_file.as_deref(), Some("/path/to/file"));
        assert_eq!(args.region.as_deref(), Some("ap-southeast-1"));
        assert_eq!(args.code.unwrap().as_str(), "123456");
        assert_eq!(args.arn.as_deref(), Some("arn:aws:iam::123:mfa/user"));
        assert_eq!(args.duration, 1800);
        assert!(args.shell);
        assert!(args.export);
        assert_eq!(args.session_profile.as_deref(), Some("session"));
    }

    #[test]
    fn test_combined_short_flags() {
        let args = parse(&["-se"]).unwrap();
        assert!(args.shell && args.export);
    }

    #[test]
    fn test_requires_an_output_mode() {
        let error = parse(&["--code", "123456"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);

        assert!(parse(&["-s"]).is_ok());
        assert!(parse(&["-e"]).is_ok());
        assert!(parse(&["-u", "session"]).is_ok());
    }

    #[test]
    fn test_rejects_invalid_code() {
        for code in ["12345", "1234567", "abcdef", "12-456", ""] {
            let error = parse(&["-e", "--code", code]).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ValueValidation, "code {code:?}");
            assert!(error.to_string().contains("exactly 6 digits"));
        }
    }

    #[test]
    fn test_mfa_process() {
        let args = parse(&[
            "-e",
            "--mfa-process",
            "ykman oath accounts code --single aws",
        ])
        .unwrap();
        assert_eq!(
            args.mfa_process.as_deref(),
            Some("ykman oath accounts code --single aws")
        );

        let error = parse(&["-e", "--mfa-process", "pass otp aws", "-c", "123456"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn test_duration_bounds() {
        assert_eq!(parse(&["-e", "-d", "900"]).unwrap().duration, 900);
        assert_eq!(parse(&["-e", "-d", "129600"]).unwrap().duration, 129600);
        assert!(parse(&["-e", "-d", "899"]).is_err());
        assert!(parse(&["-e", "-d", "129601"]).is_err());
    }

    #[test]
    fn test_format_values() {
        let format = |value: &str| parse(&["-e", "--format", value]).map(|args| args.format);
        assert_eq!(
            format("bash").unwrap(),
            Some(ExportFormat::Shell(Shell::Bash))
        );
        assert_eq!(
            format("zsh").unwrap(),
            Some(ExportFormat::Shell(Shell::Zsh))
        );
        assert_eq!(format("sh").unwrap(), Some(ExportFormat::Shell(Shell::Sh)));
        assert_eq!(
            format("cmd").unwrap(),
            Some(ExportFormat::Shell(Shell::Cmd))
        );
        assert_eq!(
            format("powershell").unwrap(),
            Some(ExportFormat::Shell(Shell::PowerShell))
        );
        assert_eq!(
            format("pwsh").unwrap(),
            Some(ExportFormat::Shell(Shell::PowerShell))
        );
        assert_eq!(format("json").unwrap(), Some(ExportFormat::Json));
        assert!(format("yaml").is_err());
    }

    #[test]
    fn test_format_lists_every_shell() {
        for shell in Shell::ALL {
            assert!(
                ExportFormat::Shell(shell).to_possible_value().is_some(),
                "{shell:?} has no --format value"
            );
        }
    }

    #[test]
    fn test_format_requires_export() {
        let error = parse(&["-s", "--format", "json"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn test_update_profile_name_must_be_valid() {
        for name in ["dev", "team/dev", "a.b@c:d+e%f_g-h"] {
            assert_eq!(
                parse(&["-u", name]).unwrap().session_profile.as_deref(),
                Some(name)
            );
        }
        for name in ["", "my session", "dev]", "dev!"] {
            let error = parse(&["-u", name]).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ValueValidation, "{name:?}");
            assert!(error.to_string().contains("ASCII letters"), "{error}");
        }
    }

    #[test]
    fn test_role_requires_export_or_shell() {
        assert_eq!(
            parse(&["-e", "--role", "dev"]).unwrap().role.as_deref(),
            Some("dev")
        );
        assert!(parse(&["-s", "-u", "session", "--role", "dev"]).is_ok());

        // The role's credentials would have nowhere to go.
        let error = parse(&["-u", "session", "--role", "dev"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
    }

    #[test]
    fn test_force_requires_update_profile() {
        let error = parse(&["-e", "--force"]).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
        assert!(parse(&["-u", "session", "--force"]).unwrap().force);
    }
}
