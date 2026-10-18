use std::io;
use std::path::PathBuf;

use miette::Diagnostic;
use thiserror::Error;

/// Every way a run can fail, with a hint on how to fix it where one helps.
#[derive(Debug, Error, Diagnostic)]
pub enum CliError {
    #[error("no output mode selected")]
    #[diagnostic(help("pass at least one of --shell/-s, --export/-e, or --update-profile/-u"))]
    NoOutputMode,

    #[error("cannot locate the AWS credentials file: no home directory")]
    #[diagnostic(help("set AWS_SHARED_CREDENTIALS_FILE or pass --credentials-file"))]
    NoCredentialsFile,

    #[error("no MFA device is assigned to this IAM user")]
    #[diagnostic(help(
        "pass the device with --arn, or set mfa_serial for the profile in ~/.aws/config"
    ))]
    NoMfaDevice,

    #[error("cannot read the MFA code")]
    #[diagnostic(help("pass the code with --code when not running in an interactive terminal"))]
    Prompt(#[source] dialoguer::Error),

    #[error("AWS {operation} failed: {message}")]
    Aws {
        operation: &'static str,
        message: String,
    },

    #[error("AWS {operation} returned no {field}")]
    IncompleteResponse {
        operation: &'static str,
        field: &'static str,
    },

    #[error("cannot update the credentials file {}", .path.display())]
    CredentialsFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("cannot start the shell `{program}`")]
    Shell {
        program: String,
        #[source]
        source: io::Error,
    },

    #[error("cannot write to stdout")]
    Stdout(#[source] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_display() {
        assert_eq!(
            CliError::NoOutputMode.to_string(),
            "no output mode selected"
        );
        assert_eq!(
            CliError::NoMfaDevice.to_string(),
            "no MFA device is assigned to this IAM user"
        );
        let aws = CliError::Aws {
            operation: "GetSessionToken",
            message: "AccessDenied: invalid MFA one time pass code".to_owned(),
        };
        assert_eq!(
            aws.to_string(),
            "AWS GetSessionToken failed: AccessDenied: invalid MFA one time pass code"
        );
        let incomplete = CliError::IncompleteResponse {
            operation: "GetCallerIdentity",
            field: "Account",
        };
        assert_eq!(
            incomplete.to_string(),
            "AWS GetCallerIdentity returned no Account"
        );
        let file = CliError::CredentialsFile {
            path: PathBuf::from("/tmp/credentials"),
            source: io::Error::other("disk full"),
        };
        assert_eq!(
            file.to_string(),
            "cannot update the credentials file /tmp/credentials"
        );
    }

    #[test]
    fn test_io_errors_keep_their_source() {
        let error = CliError::Shell {
            program: "/bin/nope".to_owned(),
            source: io::Error::new(io::ErrorKind::NotFound, "not found"),
        };
        let source = error.source().expect("the io::Error is the source");
        assert_eq!(source.to_string(), "not found");
    }

    #[test]
    fn test_actionable_errors_have_help() {
        for error in [
            CliError::NoOutputMode,
            CliError::NoCredentialsFile,
            CliError::NoMfaDevice,
        ] {
            assert!(error.help().is_some(), "{error} should explain the fix");
        }
    }
}
