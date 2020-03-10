use rusoto_core::request::BufferedHttpResponse;
use rusoto_core::{HttpDispatchError, RusotoError};
use rusoto_credential::CredentialsError;
use rusoto_iam::{
    GetUserError, GetUserRequest, Iam, IamClient, ListMFADevicesError, ListMFADevicesRequest,
    ListMFADevicesResponse,
};
use rusoto_sts::{
    GetCallerIdentityError, GetCallerIdentityRequest, GetSessionTokenError, GetSessionTokenRequest,
    Sts, StsClient,
};
// use shellexpand::tilde;
use std::collections::HashMap;
use std::process::Command;
use structopt::clap::AppSettings;
use structopt::StructOpt;

// const CONF_FILE_NAME: &str = "~/.aws/credentials";

#[cfg(not(target_os = "windows"))]
const DEFAULT_SHELL: &str = "/bin/sh";

#[cfg(target_os = "windows")]
const DEFAULT_SHELL: &str = "cmd.exe";

#[derive(StructOpt, Debug, Clone)]
#[structopt(
    name = "aws-mfa-session",
        global_settings(&[AppSettings::ColoredHelp, AppSettings::NeedsLongHelp, AppSettings::NeedsSubcommandHelp]),
)]
pub struct Args {
    /// aws credential profile
    #[structopt(long = "profile", short = "p", default_value = "default")]
    profile: String,
    /// mfa code from mfa resource
    #[structopt(long = "code", short = "c")]
    code: String,
    /// mfa code from mfa resource
    #[structopt(long = "arn", short = "a")]
    arn: Option<String>,
    /// run shell
    #[structopt(short = "s")]
    shell: bool,
}

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

pub fn run(opts: Args) -> Result<(), CliError> {
    let iam_client = IamClient::new(Default::default());

    let serial_number = match opts.arn {
        None => {
            // get mfa-device
            let mfa_request = ListMFADevicesRequest {
                marker: None,
                max_items: Some(1),
                user_name: None,
            };
            let response = iam_client.list_mfa_devices(mfa_request).sync()?;
            let ListMFADevicesResponse { mfa_devices, .. } = response;
            let serial = &mfa_devices.get(0).ok_or(CliError::NoMFA)?.serial_number;
            Some(serial.to_owned())
        }
        other => other,
    };

    // get sts credentials
    let sts_client = StsClient::new(Default::default());
    let sts_request = GetSessionTokenRequest {
        duration_seconds: None,
        serial_number,
        token_code: Some(opts.code),
    };

    let credentials = sts_client
        .get_session_token(sts_request)
        .sync()?
        .credentials
        .ok_or(CliError::NoCredentials)?;

    let identity = sts_client
        .get_caller_identity(GetCallerIdentityRequest {})
        .sync()?;

    let user = iam_client
        .get_user(GetUserRequest { user_name: None })
        .sync()?
        .user;

    let account = identity.account.ok_or(CliError::NoAccount)?;
    let ps = format!("AWS:{}@{} \\$ ", user.user_name, account);
    let shell = std::env::var("SHELL").unwrap_or_else(|_| DEFAULT_SHELL.to_owned());

    if opts.shell {
        let envs: HashMap<&str, String> = [
            ("AWS_ACCESS_KEY", credentials.access_key_id),
            ("AWS_SECRET_KEY", credentials.secret_access_key),
            ("AWS_SESSION_TOKEN", credentials.session_token),
            ("PS1", ps),
        ]
        .iter()
        .cloned()
        .collect();

        Command::new(shell).envs(envs).status()?;
    } else {
        println!("export AWS_ACCESS_KEY={}", credentials.access_key_id);
        println!("export AWS_SECRET_KEY={}", credentials.secret_access_key);
        println!("export AWS_SESSION_TOKEN={}", credentials.session_token);
        println!("export PS1='{}'", ps);
    }

    Ok(())
}
