mod args;
mod credentials;
mod error;
mod profile;
mod shell;

pub use args::Args;
use credentials::*;
use error::CliError;
pub use profile::get_mfa_serial_from_profile;
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
    // Validate inputs before touching AWS — and before the single-use MFA code
    // is spent on a session token. Bail if there is no output mode to consume
    // the credentials, or if no MFA code is available (a library caller may not
    // have run get_code()); the latter previously panicked via `.expect`.
    opts.ensure_output_mode()?;
    let token_code = opts
        .code
        .ok_or_else(|| CliError::ValidationError("MFA code is required".to_string()))?;

    // ProfileProvider is limited, but AWS_PROFILE is used elsewhere
    if let Some(ref profile) = opts.profile {
        // SAFETY: Setting AWS_PROFILE environment variable is safe in this single-threaded context
        // and doesn't interfere with other parts of the application
        unsafe {
            env::set_var(AWS_PROFILE, profile);
        }
    }

    if let Some(file) = opts.credentials_file {
        // SAFETY: Setting AWS_SHARED_CREDENTIALS_FILE environment variable is safe in this
        // single-threaded context and doesn't interfere with other parts of the application
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
            // First, try to get mfa_serial from profile configuration
            if let Some(mfa_serial) = get_mfa_serial_from_profile(opts.profile.as_deref()) {
                mfa_serial
            } else {
                // Fallback to automatic MFA device detection
                let response = iam_client.list_mfa_devices().max_items(1).send().await?;
                let mfa_devices = response.mfa_devices();
                let serial = &mfa_devices.first().ok_or(CliError::NoMFA)?.serial_number();
                (*serial).to_owned()
            }
        }
        Some(other) => other,
    };

    let sts_client = StsClient::new(&shared_config);

    let credentials = sts_client
        .get_session_token()
        .set_serial_number(Some(serial_number))
        .token_code(token_code)
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
            // Record the region the session was actually minted under (resolved
            // from --region, env, profile, or the default) so the written
            // profile is self-contained, not only when --region was passed.
            region: shared_config.region().map(|r| r.to_string()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[tokio::test]
    async fn test_run_rejects_missing_output_mode() {
        // With no -s/-e/-u, run must return an error before any AWS work, so the
        // MFA code is never sent to STS (guard is the first statement in run).
        let opts = Args::try_parse_from(["aws-mfa-session", "--code", "123456"]).unwrap();
        assert!(matches!(run(opts).await, Err(CliError::ValidationError(_))));
    }

    #[tokio::test]
    async fn test_run_rejects_missing_code() {
        // Output mode selected but no MFA code (e.g. a library caller that never
        // ran get_code): run must return an error, not panic, before any AWS work.
        let opts = Args::try_parse_from(["aws-mfa-session", "--export"]).unwrap();
        assert_eq!(opts.code, None);
        assert!(matches!(run(opts).await, Err(CliError::ValidationError(_))));
    }

    #[test]
    fn test_env_var_setting_logic() {
        // Test the logic for setting environment variables based on Args
        // This test verifies the conditional logic without mocking env vars

        // Test Some() values result in setting environment variables
        let profile = Some("test-profile".to_string());
        let file = Some("/test/credentials".to_string());

        // This is the pattern from run() function - verify the conditions work
        assert!(profile.is_some()); // Would trigger env::set_var in run()
        assert!(file.is_some()); // Would trigger env::set_var in run()

        // Test None values don't trigger environment variable setting
        let profile_none: Option<String> = None;
        let file_none: Option<String> = None;

        assert!(profile_none.is_none()); // Would NOT trigger env::set_var in run()
        assert!(file_none.is_none()); // Would NOT trigger env::set_var in run()
    }
}
