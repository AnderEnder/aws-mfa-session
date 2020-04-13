mod credentials;
mod error;
mod shell;

use credentials::*;
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

const AWS_PROFILE: &str = "AWS_PROFILE";
const AWS_DEFAULT_REGION: &str = "AWS_DEFAULT_REGION";

#[derive(StructOpt, Debug, Clone)]
#[structopt(
    name = "aws-mfa-session",
        global_settings(&[AppSettings::ColoredHelp, AppSettings::NeedsLongHelp, AppSettings::NeedsSubcommandHelp]),
)]
pub struct Args {
    /// aws credential profile to use. AWS_PROFILE is used by default
    #[structopt(long = "profile", short = "p")]
    profile: Option<String>,
    /// aws credentials file location to use. AWS_SHARED_CREDENTIALS_FILE is used if not defined
    #[structopt(long = "credentials-file", short = "f")]
    credentials_file: Option<String>,
    /// aws region. AWS_REGION is used if not defined
    #[structopt(long = "region", short = "r")]
    region: Option<Region>,
    /// mfa code from mfa resource
    #[structopt(long = "code", short = "c")]
    code: String,
    /// mfa device arn from user credentials
    #[structopt(long = "arn", short = "a")]
    arn: Option<String>,
    /// run shell with aws credentials as environment variables
    #[structopt(short = "s")]
    shell: bool,
    /// print(export) aws credentials as environment variables
    #[structopt(short = "e")]
    export: bool,
    /// update aws credential profile
    #[structopt(long = "update-profile", short = "u")]
    update_profile: Option<String>,
}

pub async fn run(opts: Args) -> Result<(), CliError> {
    // ProfileProvider is limited, but AWS_PROFILE is used elsewhere
    if let Some(profile) = opts.profile {
        env::set_var(AWS_PROFILE, profile);
    }

    if let Some(file) = opts.credentials_file {
        env::set_var(AWS_SHARED_CREDENTIALS_FILE, file);
    }

    let provider = ProfileProvider::new()?;
    let dispatcher = HttpClient::new()?;
    let client = Client::new_with(provider, dispatcher);

    let region: Region = match opts.region {
        Some(region) => region,
        None => match std::env::var(AWS_DEFAULT_REGION) {
            Ok(s) => s.parse::<Region>()?,
            _ => Default::default(),
        },
    };

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

    if let Some(name) = opts.update_profile {
        let c = credentials.clone();
        let profile = Profile {
            name,
            access_key_id: c.access_key_id,
            secret_access_key: c.secret_access_key,
            session_token: Some(c.session_token),
            region: Some(region.name().to_owned()),
        };
        update_credentials(&profile)?;
    }

    if opts.shell {
        let c = credentials.clone();
        let envs: HashMap<&str, String> = [
            ("AWS_ACCESS_KEY", c.access_key_id),
            ("AWS_SECRET_KEY", c.secret_access_key),
            ("AWS_SESSION_TOKEN", c.session_token),
            ("PS1", ps.clone()),
        ]
        .iter()
        .cloned()
        .collect();

        Command::new(shell.clone()).envs(envs).status()?;
    }

    if opts.export {
        Shell::from(shell.as_str()).export(
            credentials.access_key_id,
            credentials.secret_access_key,
            credentials.session_token,
            ps,
        );
    }

    Ok(())
}
