use std::fmt::Display;

use aws_sdk_iam::{error::ListMFADevicesError, SdkError};
use aws_sdk_sts::error::{GetCallerIdentityError, GetSessionTokenError};
use aws_types::credentials::CredentialsError;

#[derive(Debug)]
pub enum CliError {
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
            CliError::NoMFA => write!(f, "No MFA device in user profile"),
            CliError::NoCredentials => write!(f, "No returned credentials"),
            CliError::NoAccount => write!(f, "No returned account"),
            CliError::ListMFADevicesError(e) => write!(f, "No mfa devices: {}", e),
            CliError::GetSessionTokenError(e) => write!(f, "Cannot receive token: {}", e),
            CliError::GetCallerIdentityError(e) => write!(f, "Error: {}", e),
            CliError::SdkError(e) => write!(f, "Error: {}", e),
            CliError::IoError(e) => write!(f, "Error: {}", e),
        }
    }
}

impl std::error::Error for CliError {}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::IoError(e)
    }
}

impl From<CredentialsError> for CliError {
    fn from(e: CredentialsError) -> Self {
        CliError::SdkError(e.to_string())
    }
}

impl<E: Display> From<SdkError<E>> for CliError {
    fn from(e: SdkError<E>) -> Self {
        match e {
            SdkError::ConstructionFailure(e) => Self::SdkError(e.to_string()),
            SdkError::TimeoutError(e) => Self::SdkError(e.to_string()),
            SdkError::DispatchFailure(e) => Self::SdkError(e.to_string()),
            SdkError::ResponseError { err, raw: _ } => Self::SdkError(err.to_string()),
            SdkError::ServiceError { err, raw: _ } => Self::SdkError(err.to_string()),
        }
    }
}
