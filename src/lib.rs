mod credentials;
mod error;
mod shell;

use credentials::{update_credentials, Profile};
use error::CliError;
use shell::Shell;

use rusoto_core::request::HttpClient;
use rusoto_core::{Client, Region};
use rusoto_credential::ProfileProvider;
use rusoto_iam::{GetUserRequest, Iam, IamClient, ListMFADevicesRequest, ListMFADevicesResponse};
use rusoto_sts::{GetCallerIdentityRequest, GetSessionTokenRequest, Sts, StsClient};
use std::collections::HashMap;
use std::env;
use std::process::Command;
use structopt::clap::AppSettings;
use structopt::StructOpt;

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
    /// aws credential profile to use
    #[structopt(long = "profile", short = "p", default_value = "default")]
    profile: String,
    /// mfa code from mfa resource
    #[structopt(long = "code", short = "c")]
    code: String,
    /// mfa device arn from user credentials
    #[structopt(long = "arn", short = "a")]
    arn: Option<String>,
    /// run shell with aws credentials as environment variables
    #[structopt(short = "s")]
    shell: bool,
    /// update aws credential profile
    #[structopt(long = "update-profile", short = "u")]
    update_profile: Option<String>,
}

pub async fn run(opts: Args) -> Result<(), CliError> {
    // ProfileProvider is limited, but AWS_PROFILE is used elsewhere
    env::set_var("AWS_PROFILE", opts.profile);
    let provider = ProfileProvider::new()?;

    let dispatcher = HttpClient::new()?;
    let client = Client::new_with(provider, dispatcher);

    // Read region configuration from profile using AWS_PROFILE
    let region: Region = Default::default();

    let iam_client = IamClient::new_with_client(client.clone(), region.clone());

    let serial_number = match opts.arn {
        None => {
            // get mfa-device
            let mfa_request = ListMFADevicesRequest {
                marker: None,
                max_items: Some(1),
                user_name: None,
            };
            let response = iam_client.list_mfa_devices(mfa_request).await?;
            let ListMFADevicesResponse { mfa_devices, .. } = response;
            let serial = &mfa_devices.get(0).ok_or(CliError::NoMFA)?.serial_number;
            Some(serial.to_owned())
        }
        other => other,
    };

    // get sts credentials
    let sts_client = StsClient::new_with_client(client, region.clone());
    let sts_request = GetSessionTokenRequest {
        duration_seconds: None,
        serial_number,
        token_code: Some(opts.code),
    };

    let credentials = sts_client
        .get_session_token(sts_request)
        .await?
        .credentials
        .ok_or(CliError::NoCredentials)?;

    let identity = sts_client
        .get_caller_identity(GetCallerIdentityRequest {})
        .await?;

    let user = iam_client
        .get_user(GetUserRequest { user_name: None })
        .await?
        .user;

    let account = identity.account.ok_or(CliError::NoAccount)?;
    let ps = format!("AWS:{}@{} \\$ ", user.user_name, account);
    let shell = std::env::var("SHELL").unwrap_or_else(|_| DEFAULT_SHELL.to_owned());

    let credentials2 = credentials.clone();

    if let Some(name) = opts.update_profile {
        let profile = Profile {
            name,
            access_key_id: credentials2.access_key_id,
            secret_access_key: credentials2.secret_access_key,
            session_token: Some(credentials2.session_token),
            region: Some(region.name().to_owned()),
        };
        update_credentials(&profile)?;
    }

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
        Shell::from(shell.as_str()).export(
            credentials.access_key_id,
            credentials.secret_access_key,
            credentials.session_token,
            ps,
        );
    }

    Ok(())
}
