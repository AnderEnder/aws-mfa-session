use rusoto_core::request::BufferedHttpResponse;
use rusoto_core::{HttpDispatchError, RusotoError};
use rusoto_credential::CredentialsError;
use rusoto_iam::{GetUserError, ListMFADevicesError};
use rusoto_sts::{GetCallerIdentityError, GetSessionTokenError};

#[derive(Debug)]
pub enum CliError {
    NoMFA,
    NoCredentials,
    NoAccount,
    ListMFADevicesError(ListMFADevicesError),
    GetSessionTokenError(GetSessionTokenError),
    GetCallerIdentityError(GetCallerIdentityError),
    GetUserError(GetUserError),
    Credentials(CredentialsError),
    HttpDispatch(HttpDispatchError),
    RusotoOther(String),
    RusotoUnknown(BufferedHttpResponse),
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
            CliError::GetCallerIdentityError(e) => write!(f, "error: {}", e),
            CliError::GetUserError(e) => write!(f, "error: {}", e),
            CliError::Credentials(e) => write!(f, "error: {}", e),
            CliError::HttpDispatch(e) => write!(f, "error: {}", e),
            CliError::RusotoOther(e) => write!(f, "error: {}", e),
            CliError::RusotoUnknown(e) => write!(f, "rusoto error: {:?}", e),
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

impl From<RusotoError<ListMFADevicesError>> for CliError {
    fn from(e: RusotoError<ListMFADevicesError>) -> Self {
        match e {
            RusotoError::Service(e) => Self::ListMFADevicesError(e),
            RusotoError::HttpDispatch(e) => Self::HttpDispatch(e),
            RusotoError::Credentials(e) => Self::Credentials(e),
            RusotoError::Validation(e) => Self::RusotoOther(e),
            RusotoError::ParseError(e) => Self::RusotoOther(e),
            RusotoError::Unknown(e) => Self::RusotoUnknown(e),
        }
    }
}

impl From<RusotoError<GetSessionTokenError>> for CliError {
    fn from(e: RusotoError<GetSessionTokenError>) -> Self {
        match e {
            RusotoError::Service(e) => Self::GetSessionTokenError(e),
            RusotoError::HttpDispatch(e) => Self::HttpDispatch(e),
            RusotoError::Credentials(e) => Self::Credentials(e),
            RusotoError::Validation(e) => Self::RusotoOther(e),
            RusotoError::ParseError(e) => Self::RusotoOther(e),
            RusotoError::Unknown(e) => Self::RusotoUnknown(e),
        }
    }
}

impl From<RusotoError<GetUserError>> for CliError {
    fn from(e: RusotoError<GetUserError>) -> Self {
        match e {
            RusotoError::Service(e) => Self::GetUserError(e),
            RusotoError::Credentials(e) => Self::Credentials(e),
            RusotoError::HttpDispatch(e) => Self::HttpDispatch(e),
            RusotoError::Validation(e) => Self::RusotoOther(e),
            RusotoError::ParseError(e) => Self::RusotoOther(e),
            RusotoError::Unknown(e) => Self::RusotoUnknown(e),
        }
    }
}

impl From<RusotoError<GetCallerIdentityError>> for CliError {
    fn from(e: RusotoError<GetCallerIdentityError>) -> Self {
        match e {
            RusotoError::Service(e) => Self::GetCallerIdentityError(e),
            RusotoError::Credentials(e) => Self::Credentials(e),
            RusotoError::HttpDispatch(e) => Self::HttpDispatch(e),
            RusotoError::Validation(e) => Self::RusotoOther(e),
            RusotoError::ParseError(e) => Self::RusotoOther(e),
            RusotoError::Unknown(e) => Self::RusotoUnknown(e),
        }
    }
}
