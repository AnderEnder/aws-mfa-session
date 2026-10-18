//! The AWS calls a run makes, behind a trait so the session flow can be tested
//! without network access.

use std::error::Error;
use std::fmt::Debug;
use std::time::SystemTime;

use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_runtime::env_config::file::{EnvConfigFileKind, EnvConfigFiles};
use aws_sdk_sts::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use tokio::sync::OnceCell;

use crate::config::SdkSettings;
use crate::error::CliError;
use crate::mfa::MfaCode;
use crate::session::{Identity, SessionCredentials};

/// Used when no region is configured anywhere; STS and IAM are global services,
/// so any region works for the calls this tool makes.
const FALLBACK_REGION: &str = "us-east-1";

pub(crate) trait AwsApi {
    /// Who the long-term credentials belong to. Always permitted, so it doubles
    /// as a check that the credentials work.
    async fn caller_identity(&self) -> Result<Identity, CliError>;

    /// The serial numbers (ARNs for virtual devices) of the caller's MFA devices.
    async fn mfa_devices(&self) -> Result<Vec<String>, CliError>;

    /// Exchange the long-term credentials and an MFA code for session credentials.
    async fn session_token(
        &self,
        mfa_device: &str,
        code: &MfaCode,
        duration_secs: i32,
    ) -> Result<SessionCredentials, CliError>;

    /// The region the calls are made in, recorded in saved profiles.
    async fn region(&self) -> Option<String>;
}

/// [`AwsApi`] backed by the AWS SDK.
pub(crate) struct SdkAws {
    settings: SdkSettings,
    clients: OnceCell<Clients>,
}

struct Clients {
    iam: aws_sdk_iam::Client,
    sts: aws_sdk_sts::Client,
    region: Option<String>,
}

impl SdkAws {
    pub fn new(settings: SdkSettings) -> Self {
        Self {
            settings,
            clients: OnceCell::new(),
        }
    }

    /// The clients are built on first use, so runs that never call AWS (such
    /// as reusing a still-valid profile) skip region and credential discovery.
    async fn clients(&self) -> &Clients {
        self.clients
            .get_or_init(|| async {
                let config = load_config(&self.settings).await;
                Clients {
                    iam: aws_sdk_iam::Client::new(&config),
                    sts: aws_sdk_sts::Client::new(&config),
                    region: config.region().map(ToString::to_string),
                }
            })
            .await
    }
}

async fn load_config(settings: &SdkSettings) -> SdkConfig {
    let mut loader = aws_config::defaults(BehaviorVersion::latest());
    if let Some(profile) = &settings.profile {
        loader = loader.profile_name(profile);
    }
    if let Some(file) = &settings.credentials_file {
        let files = EnvConfigFiles::builder()
            .include_default_config_file(true)
            .with_file(EnvConfigFileKind::Credentials, file)
            .build();
        loader = loader.profile_files(files);
    }
    if let Some(region) = &settings.region {
        loader = loader.region(Region::new(region.clone()));
    }

    let config = loader.load().await;
    if config.region().is_some() {
        config
    } else {
        config
            .into_builder()
            .region(Region::new(FALLBACK_REGION))
            .build()
    }
}

impl AwsApi for SdkAws {
    async fn caller_identity(&self) -> Result<Identity, CliError> {
        const OPERATION: &str = "GetCallerIdentity";
        let output = self
            .clients()
            .await
            .sts
            .get_caller_identity()
            .send()
            .await
            .map_err(|e| aws_error(OPERATION, e))?;
        let missing = |field| CliError::IncompleteResponse {
            operation: OPERATION,
            field,
        };
        Ok(Identity {
            account: output.account.ok_or_else(|| missing("Account"))?,
            arn: output.arn.ok_or_else(|| missing("Arn"))?,
        })
    }

    async fn mfa_devices(&self) -> Result<Vec<String>, CliError> {
        let output = self
            .clients()
            .await
            .iam
            .list_mfa_devices()
            .send()
            .await
            .map_err(|e| aws_error("ListMFADevices", e))?;
        Ok(output
            .mfa_devices()
            .iter()
            .map(|device| device.serial_number().to_owned())
            .collect())
    }

    async fn session_token(
        &self,
        mfa_device: &str,
        code: &MfaCode,
        duration_secs: i32,
    ) -> Result<SessionCredentials, CliError> {
        const OPERATION: &str = "GetSessionToken";
        let output = self
            .clients()
            .await
            .sts
            .get_session_token()
            .serial_number(mfa_device)
            .token_code(code.as_str())
            .duration_seconds(duration_secs)
            .send()
            .await
            .map_err(|e| aws_error(OPERATION, e))?;
        let credentials = output.credentials().ok_or(CliError::IncompleteResponse {
            operation: OPERATION,
            field: "Credentials",
        })?;
        Ok(SessionCredentials::from(credentials))
    }

    async fn region(&self) -> Option<String> {
        self.clients().await.region.clone()
    }
}

impl From<&aws_sdk_sts::types::Credentials> for SessionCredentials {
    fn from(credentials: &aws_sdk_sts::types::Credentials) -> Self {
        Self {
            access_key_id: credentials.access_key_id().to_owned(),
            secret_access_key: credentials.secret_access_key().to_owned(),
            session_token: credentials.session_token().to_owned(),
            expiration: SystemTime::try_from(*credentials.expiration()).ok(),
        }
    }
}

/// Describe a failed call: `Code: message` for errors returned by the service
/// (such as a wrong MFA code), or the chain of causes for everything else
/// (such as missing credentials or no network). The full error is logged at
/// debug level, for bug reports.
fn aws_error<E, R>(operation: &'static str, error: SdkError<E, R>) -> CliError
where
    E: ProvideErrorMetadata + Error + 'static,
    R: Debug,
{
    tracing::debug!(operation, error = %DisplayErrorContext(&error), "AWS call failed");
    let message = match (error.code(), error.message()) {
        (Some(code), Some(message)) => format!("{code}: {}", message.trim()),
        _ => causes(&error),
    };
    CliError::Aws { operation, message }
}

/// An error and its sources, as `outer: inner: innermost`.
fn causes(error: &dyn Error) -> String {
    let mut messages = vec![error.to_string()];
    let mut source = error.source();
    while let Some(error) = source {
        messages.push(error.to_string());
        source = error.source();
    }
    messages.join(": ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_sts::error::ErrorMetadata;
    use aws_sdk_sts::operation::get_session_token::GetSessionTokenError;
    use aws_sdk_sts::primitives::DateTime;

    #[test]
    fn test_aws_error_for_service_error() {
        let service_error = GetSessionTokenError::generic(
            ErrorMetadata::builder()
                .code("AccessDenied")
                .message("MultiFactorAuthentication failed with invalid MFA one time pass code. ")
                .build(),
        );
        let error = aws_error(
            "GetSessionToken",
            SdkError::service_error(service_error, ()),
        );
        assert_eq!(
            error.to_string(),
            "AWS GetSessionToken failed: AccessDenied: MultiFactorAuthentication failed with \
             invalid MFA one time pass code."
        );
    }

    #[test]
    fn test_aws_error_for_client_side_failure() {
        let error: SdkError<GetSessionTokenError, ()> =
            SdkError::construction_failure(std::io::Error::other("no credentials in profile"));
        let error = aws_error("GetSessionToken", error);
        assert_eq!(
            error.to_string(),
            "AWS GetSessionToken failed: failed to construct request: no credentials in profile"
        );
    }

    #[test]
    fn test_credentials_conversion() {
        let sts = aws_sdk_sts::types::Credentials::builder()
            .access_key_id("ASIAKEY")
            .secret_access_key("secret")
            .session_token("token")
            .expiration(DateTime::from_secs(1_800_000_000))
            .build()
            .unwrap();
        let credentials = SessionCredentials::from(&sts);
        assert_eq!(credentials.access_key_id, "ASIAKEY");
        assert_eq!(credentials.secret_access_key, "secret");
        assert_eq!(credentials.session_token, "token");
        assert_eq!(
            credentials.expiration,
            Some(crate::session::tests::at(1_800_000_000))
        );
    }

    #[tokio::test]
    async fn test_explicit_region_is_used() {
        let aws = SdkAws::new(SdkSettings {
            region: Some("eu-central-1".to_owned()),
            ..SdkSettings::default()
        });
        assert_eq!(aws.region().await.as_deref(), Some("eu-central-1"));
    }
}
