use std::fmt::{Debug, Display};

use aws_sdk_iam::{error::SdkError, operation::list_mfa_devices::ListMFADevicesError};
use aws_sdk_sts::operation::{
    get_caller_identity::GetCallerIdentityError, get_session_token::GetSessionTokenError,
};

#[derive(Debug)]
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
            CliError::ValidationError(e) => write!(f, "Validation error: {}", e),
            CliError::NoMFA => write!(f, "No MFA device in user profile"),
            CliError::NoCredentials => write!(f, "No returned credentials"),
            CliError::NoAccount => write!(f, "No returned account"),
            CliError::ListMFADevicesError(e) => write!(f, "No mfa devices: {:?}", e),
            CliError::GetSessionTokenError(e) => write!(f, "Cannot receive token: {:?}", e),
            CliError::GetCallerIdentityError(e) => write!(f, "Error: {:?}", e),
            CliError::SdkError(e) => write!(f, "SDKError: {:?}", e),
            CliError::IoError(e) => write!(f, "IOError: {:?}", e),
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
            SdkError::ConstructionFailure(e) => Self::SdkError(format!("{:?}", e)),
            SdkError::TimeoutError(e) => Self::SdkError(format!("{:?}", e)),
            SdkError::DispatchFailure(e) => Self::SdkError(format!("{:?}", e)),
            SdkError::ResponseError(e) => Self::SdkError(format!("{:?}", e)),
            SdkError::ServiceError(e) => Self::SdkError(format!("{:?}", e)),
            _ => Self::SdkError("Unknown SDK error".to_string()),
        }
    }
}
