use rusoto_core::request::{BufferedHttpResponse, TlsError};
use rusoto_core::RusotoError;
use rusoto_credential::CredentialsError;
use rusoto_iam::{GetUserError, ListMFADevicesError};
use rusoto_signature::region::ParseRegionError;
use rusoto_sts::{GetCallerIdentityError, GetSessionTokenError};

#[derive(Debug)]
pub enum CliError {
    NoMFA,
    NoCredentials,
    NoAccount,
    ListMFADevicesError(ListMFADevicesError),
    GetSessionTokenError(GetSessionTokenError),
    GetCallerIdentityError(GetCallerIdentityError),
    Rusoto(String),
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
            CliError::GetCallerIdentityError(e) => write!(f, "Error: {}", e),
            CliError::Rusoto(e) => write!(f, "Error: {}", e),
            CliError::RusotoUnknown(e) => write!(f, "Error:\n{}", e.body_as_str()),
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
        CliError::Rusoto(e.message)
    }
}

impl From<TlsError> for CliError {
    fn from(e: TlsError) -> Self {
        CliError::Rusoto(e.to_string())
    }
}

impl From<RusotoError<ListMFADevicesError>> for CliError {
    fn from(e: RusotoError<ListMFADevicesError>) -> Self {
        match e {
            RusotoError::Service(e) => Self::Rusoto(e.to_string()),
            RusotoError::HttpDispatch(e) => Self::Rusoto(e.to_string()),
            RusotoError::Credentials(e) => Self::Rusoto(e.to_string()),
            RusotoError::Validation(e) => Self::Rusoto(e),
            RusotoError::ParseError(e) => Self::Rusoto(e),
            RusotoError::Unknown(e) => Self::RusotoUnknown(e),
            RusotoError::Blocking => Self::Rusoto("Blocking".to_owned()),
        }
    }
}

impl From<RusotoError<GetSessionTokenError>> for CliError {
    fn from(e: RusotoError<GetSessionTokenError>) -> Self {
        match e {
            RusotoError::Service(e) => Self::Rusoto(e.to_string()),
            RusotoError::HttpDispatch(e) => Self::Rusoto(e.to_string()),
            RusotoError::Credentials(e) => Self::Rusoto(e.to_string()),
            RusotoError::Validation(e) => Self::Rusoto(e),
            RusotoError::ParseError(e) => Self::Rusoto(e),
            RusotoError::Unknown(e) => Self::RusotoUnknown(e),
            RusotoError::Blocking => Self::Rusoto("Blocking".to_owned()),
        }
    }
}

impl From<RusotoError<GetUserError>> for CliError {
    fn from(e: RusotoError<GetUserError>) -> Self {
        match e {
            RusotoError::Service(e) => Self::Rusoto(e.to_string()),
            RusotoError::Credentials(e) => Self::Rusoto(e.to_string()),
            RusotoError::HttpDispatch(e) => Self::Rusoto(e.to_string()),
            RusotoError::Validation(e) => Self::Rusoto(e),
            RusotoError::ParseError(e) => Self::Rusoto(e),
            RusotoError::Unknown(e) => Self::RusotoUnknown(e),
            RusotoError::Blocking => Self::Rusoto("Blocking".to_owned()),
        }
    }
}

impl From<RusotoError<GetCallerIdentityError>> for CliError {
    fn from(e: RusotoError<GetCallerIdentityError>) -> Self {
        match e {
            RusotoError::Service(e) => Self::GetCallerIdentityError(e),
            RusotoError::Credentials(e) => Self::Rusoto(e.to_string()),
            RusotoError::HttpDispatch(e) => Self::Rusoto(e.to_string()),
            RusotoError::Validation(e) => Self::Rusoto(e),
            RusotoError::ParseError(e) => Self::Rusoto(e),
            RusotoError::Unknown(e) => Self::RusotoUnknown(e),
            RusotoError::Blocking => Self::Rusoto("Blocking".to_owned()),
        }
    }
}
impl From<ParseRegionError> for CliError {
    fn from(e: ParseRegionError) -> Self {
        Self::Rusoto(e.to_string())
    }
}
