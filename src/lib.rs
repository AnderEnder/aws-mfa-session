mod args;
mod credentials;
mod error;
mod shell;

pub use args::Args;
use credentials::*;
use error::CliError;
use shell::Shell;

use std::collections::HashMap;
use std::env;
use std::io;
use std::process::Command;

use aws_config::{BehaviorVersion, Region, meta::credentials::CredentialsProviderChain};
use aws_sdk_iam::Client;
use aws_sdk_sts::Client as StsClient;

#[cfg(not(target_os = "windows"))]
const DEFAULT_SHELL: &str = "/bin/sh";

#[cfg(target_os = "windows")]
const DEFAULT_SHELL: &str = "cmd.exe";

const AWS_PROFILE: &str = "AWS_PROFILE";
const AWS_DEFAULT_REGION: &str = "AWS_DEFAULT_REGION";

const AWS_SHARED_CREDENTIALS_FILE: &str = "AWS_SHARED_CREDENTIALS_FILE";

pub async fn run(opts: Args) -> Result<(), CliError> {
    // ProfileProvider is limited, but AWS_PROFILE is used elsewhere
    if let Some(profile) = opts.profile {
        unsafe {
            env::set_var(AWS_PROFILE, profile);
        }
    }

    if let Some(file) = opts.credentials_file {
        unsafe {
            env::set_var(AWS_SHARED_CREDENTIALS_FILE, file);
        }
    }

    let region_provider =
        aws_config::meta::region::RegionProviderChain::first_try(opts.region.clone())
            .or_default_provider()
            .or_else(env::var(AWS_DEFAULT_REGION).ok().map(Region::new))
            .or_else(Region::new("us-east-1"));

    let credentials_provider = CredentialsProviderChain::default_provider().await;
    let shared_config = aws_config::defaults(BehaviorVersion::latest())
        .region(region_provider)
        .credentials_provider(credentials_provider)
        .load()
        .await;

    let iam_client = Client::new(&shared_config);
    let serial_number = match opts.arn {
        None => {
            // let response = iam_client.list_mfa_devices(mfa_request).await?;
            let response = iam_client.list_mfa_devices().max_items(1).send().await?;

            let mfa_devices = response.mfa_devices();
            let serial = &mfa_devices.first().ok_or(CliError::NoMFA)?.serial_number();
            (*serial).to_owned()
        }
        Some(other) => other,
    };

    let sts_client = StsClient::new(&shared_config);

    let credentials = sts_client
        .get_session_token()
        .set_serial_number(Some(serial_number))
        .token_code(opts.code)
        .duration_seconds(opts.duration)
        .send()
        .await?
        .credentials()
        .map(ToOwned::to_owned)
        .ok_or(CliError::NoCredentials)?;

    let identity = sts_client.get_caller_identity().send().await?;

    let user = iam_client
        .get_user()
        .send()
        .await?
        .user()
        .map(ToOwned::to_owned)
        .ok_or(CliError::NoAccount)?;

    let account = identity.account.ok_or(CliError::NoAccount)?;
    let ps = format!("AWS:{}@{} \\$ ", user.user_name(), account);
    let shell = std::env::var("SHELL").unwrap_or_else(|_| DEFAULT_SHELL.to_owned());

    if let Some(name) = opts.session_profile {
        let c = credentials.clone();
        let profile = Profile {
            name,
            access_key_id: c.access_key_id().to_owned(),
            secret_access_key: c.secret_access_key().to_owned(),
            session_token: Some(c.session_token().to_owned()),
            region: opts.region.map(|r| r.to_string()),
        };
        update_credentials(&profile)?;
    }

    if opts.shell {
        let c = credentials.clone();
        let envs: HashMap<&str, String> = [
            ("AWS_ACCESS_KEY_ID", c.access_key_id().to_owned()),
            ("AWS_SECRET_ACCESS_KEY", c.secret_access_key().to_owned()),
            ("AWS_SESSION_TOKEN", c.session_token().to_owned()),
            ("PS1", ps.clone()),
        ]
        .iter()
        .cloned()
        .collect();

        Command::new(shell.clone()).envs(envs).status()?;
    }

    if opts.export {
        let mut stdout = io::stdout().lock();
        Shell::from(shell.as_str()).export(
            &mut stdout,
            credentials.access_key_id(),
            credentials.secret_access_key(),
            credentials.session_token(),
            &ps,
        )?;
    }

    Ok(())
}
