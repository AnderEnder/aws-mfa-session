mod credentials;
mod error;
mod shell;

use credentials::*;
use error::CliError;
use shell::Shell;

use std::collections::HashMap;
use std::env;
use std::process::Command;

use aws_config::{BehaviorVersion, Region, meta::credentials::CredentialsProviderChain};
use aws_sdk_iam::Client;
use aws_sdk_sts::Client as StsClient;
use clap::Parser;

#[cfg(not(target_os = "windows"))]
const DEFAULT_SHELL: &str = "/bin/sh";

#[cfg(target_os = "windows")]
const DEFAULT_SHELL: &str = "cmd.exe";

const AWS_PROFILE: &str = "AWS_PROFILE";
const AWS_DEFAULT_REGION: &str = "AWS_DEFAULT_REGION";

fn region(s: &str) -> Result<Region, CliError> {
    Ok(Region::new(s.to_owned()))
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "aws-mfa-session",
    about = "AWS MFA session manager",
    long_about = None,
)]
pub struct Args {
    /// AWS credential profile to use. AWS_PROFILE is used by default
    #[arg(long = "profile", short = 'p')]
    profile: Option<String>,
    /// AWS credentials file location to use. AWS_SHARED_CREDENTIALS_FILE is used if not defined
    #[arg(long = "credentials-file", short = 'f')]
    file: Option<String>,
    /// AWS region. AWS_REGION is used if not defined
    #[arg(long = "region", short = 'r', value_parser = region)]
    region: Option<Region>,
    /// MFA code from MFA resource
    #[arg(long = "code", short = 'c')]
    code: String,
    /// MFA device ARN from user profile. It could be detected automatically
    #[arg(long = "arn", short = 'a')]
    arn: Option<String>,
    /// Run shell with AWS credentials as environment variables
    #[arg(short = 's')]
    shell: bool,
    /// Print(export) AWS credentials as environment variables
    #[arg(short = 'e')]
    export: bool,
    /// Update AWS credential profile with temporary session credentials
    #[arg(long = "update-profile", short = 'u')]
    session_profile: Option<String>,
}

pub async fn run(opts: Args) -> Result<(), CliError> {
    if !opts.code.chars().all(char::is_numeric) || opts.code.len() != 6 {
        return Err(CliError::SdkError(
            "MFA code must be exactly 6 digits".to_string(),
        ));
    }

    // ProfileProvider is limited, but AWS_PROFILE is used elsewhere
    if let Some(profile) = opts.profile {
        unsafe {
            env::set_var(AWS_PROFILE, profile);
        }
    }

    if let Some(file) = opts.file {
        unsafe {
            env::set_var(AWS_SHARED_CREDENTIALS_FILE, file);
        }
    }

    let region = match opts.region {
        Some(region) => region,
        None => match std::env::var(AWS_DEFAULT_REGION) {
            Ok(s) => region(&s)?,
            _ => Region::new("us-east-1"),
        },
    };

    let region_provider = aws_config::meta::region::RegionProviderChain::first_try(region.clone())
        .or_default_provider();

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
            region: Some(region.to_string()),
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
        Shell::from(shell.as_str()).export(
            credentials.access_key_id(),
            credentials.secret_access_key(),
            credentials.session_token(),
            &ps,
        );
    }

    Ok(())
}
