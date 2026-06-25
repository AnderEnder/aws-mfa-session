use std::fmt::{Debug, Display};

use aws_sdk_iam::error::SdkError;
use miette::Diagnostic;
use thiserror::Error;

#[derive(Debug, Error, Diagnostic)]
pub enum CliError {
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("No MFA device in user profile")]
    NoMFA,
    #[error("No returned credentials")]
    NoCredentials,
    #[error("No returned account")]
    NoAccount,
    #[error("SDKError: {0}")]
    SdkError(String),
    #[error("IOError: {0}")]
    IoError(#[from] std::io::Error),
}

// thiserror's `#[from]` only generates `From` for a concrete type, so the
// generic conversion that collapses every SDK operation error stays manual.
impl<E: Display + Debug> From<SdkError<E>> for CliError {
    fn from(e: SdkError<E>) -> Self {
        CliError::SdkError(format!("{e:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_cli_error_display() {
        let validation_error = CliError::ValidationError("Invalid input".to_string());
        assert_eq!(
            validation_error.to_string(),
            "Validation error: Invalid input"
        );

        let no_mfa_error = CliError::NoMFA;
        assert_eq!(no_mfa_error.to_string(), "No MFA device in user profile");

        let no_credentials_error = CliError::NoCredentials;
        assert_eq!(no_credentials_error.to_string(), "No returned credentials");

        let no_account_error = CliError::NoAccount;
        assert_eq!(no_account_error.to_string(), "No returned account");
    }

    #[test]
    fn test_cli_error_debug() {
        let validation_error = CliError::ValidationError("test".to_string());
        let debug_str = format!("{validation_error:?}");
        assert!(debug_str.contains("ValidationError"));
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let cli_error: CliError = io_error.into();

        match cli_error {
            CliError::IoError(_) => {}
            _ => panic!("Expected IoError variant"),
        }
    }

    #[test]
    fn test_sdk_error_conversion() {
        // Any SDK operation error collapses to CliError::SdkError via the generic
        // From<SdkError<E>>. construction_failure needs no concrete operation error.
        let sdk_error: SdkError<std::io::Error> =
            SdkError::construction_failure(std::io::Error::other("boom"));
        let cli_error: CliError = sdk_error.into();

        match cli_error {
            CliError::SdkError(msg) => assert!(msg.contains("ConstructionFailure")),
            _ => panic!("Expected SdkError variant"),
        }
    }

    #[test]
    fn test_cli_error_is_error_trait() {
        let error = CliError::ValidationError("test".to_string());
        let _: &dyn Error = &error;
    }

    #[test]
    fn test_cli_error_source() {
        let validation_error = CliError::ValidationError("test".to_string());
        assert!(validation_error.source().is_none());

        // IoError variant contains the source error
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let cli_error = CliError::IoError(io_error);
        // Check that we can access the source
        match cli_error {
            CliError::IoError(ref inner) => {
                assert_eq!(inner.kind(), std::io::ErrorKind::NotFound);
            }
            _ => panic!("Expected IoError variant"),
        }
    }

    #[test]
    fn test_all_error_variants() {
        let errors = vec![
            CliError::ValidationError("test".to_string()),
            CliError::NoMFA,
            CliError::NoCredentials,
            CliError::NoAccount,
            CliError::SdkError("SDK error".to_string()),
            CliError::IoError(std::io::Error::other("test")),
        ];

        for error in errors {
            // Ensure all variants can be displayed and debugged
            let _display = error.to_string();
            let _debug = format!("{error:?}");
        }
    }
}
