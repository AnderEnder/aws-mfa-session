use std::fmt::{Debug, Display};

use aws_sdk_iam::{error::SdkError, operation::list_mfa_devices::ListMFADevicesError};
use aws_sdk_sts::operation::{
    get_caller_identity::GetCallerIdentityError, get_session_token::GetSessionTokenError,
};
use miette::Diagnostic;

#[derive(Debug, Diagnostic)]
pub enum CliError {
    ValidationError(String),
    NoMFA,
    NoCredentials,
    NoAccount,
    ListMFADevicesError(ListMFADevicesError),
    GetSessionTokenError(GetSessionTokenError),
    GetCallerIdentityError(GetCallerIdentityError),
    SdkError(String),
    IoError(std::io::Error),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CliError::ValidationError(e) => write!(f, "Validation error: {e}"),
            CliError::NoMFA => write!(f, "No MFA device in user profile"),
            CliError::NoCredentials => write!(f, "No returned credentials"),
            CliError::NoAccount => write!(f, "No returned account"),
            CliError::ListMFADevicesError(e) => write!(f, "No mfa devices: {e:?}"),
            CliError::GetSessionTokenError(e) => write!(f, "Cannot receive token: {e:?}"),
            CliError::GetCallerIdentityError(e) => write!(f, "Error: {e:?}"),
            CliError::SdkError(e) => write!(f, "SDKError: {e:?}"),
            CliError::IoError(e) => write!(f, "IOError: {e:?}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::IoError(e)
    }
}

impl<E: Display + Debug> From<SdkError<E>> for CliError {
    fn from(e: SdkError<E>) -> Self {
        match e {
            SdkError::ConstructionFailure(e) => Self::SdkError(format!("{e:?}")),
            SdkError::TimeoutError(e) => Self::SdkError(format!("{e:?}")),
            SdkError::DispatchFailure(e) => Self::SdkError(format!("{e:?}")),
            SdkError::ResponseError(e) => Self::SdkError(format!("{e:?}")),
            SdkError::ServiceError(e) => Self::SdkError(format!("{e:?}")),
            _ => Self::SdkError("Unknown SDK error".to_string()),
        }
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
            CliError::IoError(std::io::Error::new(std::io::ErrorKind::Other, "test")),
        ];

        for error in errors {
            // Ensure all variants can be displayed and debugged
            let _display = error.to_string();
            let _debug = format!("{error:?}");
        }
    }
}
