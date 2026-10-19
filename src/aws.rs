//! The AWS calls a run makes, behind a trait so the session flow can be tested
//! without network access.

use std::error::Error;
use std::fmt::Debug;
use std::time::SystemTime;

use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_runtime::env_config::file::{EnvConfigFileKind, EnvConfigFiles};
use aws_sdk_sts::config::Credentials;
use aws_sdk_sts::error::{DisplayErrorContext, ProvideErrorMetadata, SdkError};
use aws_sdk_sts::types::PolicyDescriptorType;
use tokio::sync::OnceCell;

use crate::config::SdkSettings;
use crate::error::CliError;
use crate::mfa::MfaCode;
use crate::role::RoleRequest;
use crate::session::{Identity, Session, SessionCredentials};

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

    /// Assume `role` with the MFA `session` credentials, which carry the MFA
    /// authentication that role trust policies check.
    async fn assume_role(
        &self,
        session: &SessionCredentials,
        role: &RoleRequest,
    ) -> Result<Session, CliError>;

    /// The region the calls are made in, recorded in saved profiles.
    async fn region(&self) -> Option<String>;
}

/// [`AwsApi`] backed by the AWS SDK.
pub(crate) struct SdkAws {
    settings: SdkSettings,
    clients: OnceCell<Clients>,
}

struct Clients {
    config: SdkConfig,
    iam: aws_sdk_iam::Client,
    sts: aws_sdk_sts::Client,
    region: Option<String>,
}

impl Clients {
    fn new(config: SdkConfig) -> Self {
        Self {
            iam: aws_sdk_iam::Client::new(&config),
            sts: aws_sdk_sts::Client::new(&config),
            region: config.region().map(ToString::to_string),
            config,
        }
    }
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
            .get_or_init(|| async { Clients::new(load_config(&self.settings).await) })
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

    async fn assume_role(
        &self,
        session: &SessionCredentials,
        role: &RoleRequest,
    ) -> Result<Session, CliError> {
        const OPERATION: &str = "AssumeRole";
        let credentials = Credentials::new(
            &session.access_key_id,
            &session.secret_access_key,
            Some(session.session_token.clone()),
            session.expiration,
            "aws-mfa-session",
        );
        let config = aws_sdk_sts::config::Builder::from(&self.clients().await.config)
            .credentials_provider(credentials)
            .build();
        let policy_arns: Vec<_> = role
            .policy_arns
            .iter()
            .map(|arn| PolicyDescriptorType::builder().arn(arn).build())
            .collect();
        let output = aws_sdk_sts::Client::from_conf(config)
            .assume_role()
            .role_arn(&role.arn)
            .role_session_name(&role.session_name)
            .set_external_id(role.external_id.clone())
            .set_duration_seconds(role.duration_secs)
            .set_policy_arns((!policy_arns.is_empty()).then_some(policy_arns))
            .set_policy(role.policy.clone())
            .send()
            .await
            .map_err(|e| aws_error(OPERATION, e))?;
        let missing = |field| CliError::IncompleteResponse {
            operation: OPERATION,
            field,
        };
        let credentials = output.credentials().ok_or_else(|| missing("Credentials"))?;
        let user = output
            .assumed_role_user()
            .ok_or_else(|| missing("AssumedRoleUser"))?;
        Ok(Session {
            credentials: SessionCredentials::from(credentials),
            identity: Some(Identity::from_arn(user.arn())),
        })
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
    use crate::session::tests::at;
    use aws_sdk_sts::config::SharedCredentialsProvider;
    use aws_sdk_sts::error::ErrorMetadata;
    use aws_sdk_sts::operation::get_session_token::GetSessionTokenError;
    use aws_sdk_sts::primitives::DateTime;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};
    use std::thread;

    const ROLE_ARN: &str = "arn:aws:iam::222222222222:role/AdminRole";

    /// A local stand-in for the STS and IAM endpoints. It answers each
    /// query-protocol request with a canned response for its `Action`, and
    /// records the request.
    struct MockEndpoint {
        url: String,
        requests: Arc<Mutex<Vec<MockRequest>>>,
    }

    #[derive(Clone, Debug)]
    struct MockRequest {
        params: HashMap<String, String>,
        /// The access key that signed the request.
        signed_by: String,
        session_token: Option<String>,
    }

    impl MockEndpoint {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let requests = Arc::<Mutex<Vec<MockRequest>>>::default();
            let recorded = requests.clone();
            thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let recorded = recorded.clone();
                    thread::spawn(move || serve(stream, &recorded));
                }
            });
            Self { url, requests }
        }

        /// [`SdkAws`] calling this endpoint with long-term credentials.
        fn aws(&self) -> SdkAws {
            let credentials = Credentials::new("AKIALONGTERM", "secret", None, None, "test");
            let config = SdkConfig::builder()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new("us-east-1"))
                .endpoint_url(&self.url)
                .credentials_provider(SharedCredentialsProvider::new(credentials))
                .build();
            SdkAws {
                settings: SdkSettings::default(),
                clients: OnceCell::new_with(Some(Clients::new(config))),
            }
        }

        fn requests(&self) -> Vec<MockRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    /// Answer HTTP/1.1 requests on `stream` until the client closes it.
    fn serve(stream: TcpStream, recorded: &Mutex<Vec<MockRequest>>) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut writer = stream;
        let mut request_line = String::new();
        while reader.read_line(&mut request_line).unwrap_or(0) > 0 {
            let mut headers = HashMap::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let Some((name, value)) = line.trim_end().split_once(':') else {
                    break;
                };
                headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
            }
            let length = headers
                .get("content-length")
                .map_or(0, |n| n.parse().unwrap());
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();

            let params = parse_form(&String::from_utf8(body).unwrap());
            let (status, response) = respond(&params);
            let signed_by = headers
                .get("authorization")
                .and_then(|auth| auth.split("Credential=").nth(1))
                .and_then(|credential| credential.split('/').next())
                .unwrap_or_default()
                .to_owned();
            recorded.lock().unwrap().push(MockRequest {
                params,
                signed_by,
                session_token: headers.get("x-amz-security-token").cloned(),
            });
            write!(
                writer,
                "HTTP/1.1 {status}\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\r\n{response}",
                response.len()
            )
            .unwrap();
            request_line.clear();
        }
    }

    fn respond(params: &HashMap<String, String>) -> (&'static str, String) {
        let ok = |action: &str, result: &str| {
            let xmlns = match action {
                "ListMFADevices" => "https://iam.amazonaws.com/doc/2010-05-08/",
                _ => "https://sts.amazonaws.com/doc/2011-06-15/",
            };
            let response = format!(
                "<{action}Response xmlns=\"{xmlns}\"><{action}Result>{result}</{action}Result>\
                 <ResponseMetadata><RequestId>1</RequestId></ResponseMetadata></{action}Response>"
            );
            ("200 OK", response)
        };
        let credentials = |key: &str| {
            format!(
                "<Credentials><AccessKeyId>{key}</AccessKeyId><SecretAccessKey>s</SecretAccessKey>\
                 <SessionToken>t</SessionToken><Expiration>2027-01-15T08:00:00Z</Expiration></Credentials>"
            )
        };
        match params["Action"].as_str() {
            "GetCallerIdentity" => ok(
                "GetCallerIdentity",
                "<Arn>arn:aws:iam::111111111111:user/alice</Arn><UserId>AIDA</UserId>\
                 <Account>111111111111</Account>",
            ),
            "ListMFADevices" => ok(
                "ListMFADevices",
                "<MFADevices><member><UserName>alice</UserName>\
                 <SerialNumber>arn:aws:iam::111111111111:mfa/alice</SerialNumber>\
                 <EnableDate>2020-01-01T00:00:00Z</EnableDate></member></MFADevices>\
                 <IsTruncated>false</IsTruncated>",
            ),
            "GetSessionToken" if params["TokenCode"] == "000000" => (
                "403 Forbidden",
                "<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code>\
                 <Message>MultiFactorAuthentication failed with invalid MFA one time pass code. </Message>\
                 </Error><RequestId>1</RequestId></ErrorResponse>"
                    .to_owned(),
            ),
            "GetSessionToken" => ok("GetSessionToken", &credentials("ASIASESSION")),
            "AssumeRole" => ok(
                "AssumeRole",
                &format!(
                    "{}<AssumedRoleUser><AssumedRoleId>AROA:{name}</AssumedRoleId>\
                     <Arn>arn:aws:sts::222222222222:assumed-role/AdminRole/{name}</Arn>\
                     </AssumedRoleUser>",
                    credentials("ASIAROLE"),
                    name = params["RoleSessionName"]
                ),
            ),
            action => panic!("unexpected action {action}"),
        }
    }

    /// Decode an `application/x-www-form-urlencoded` body.
    fn parse_form(body: &str) -> HashMap<String, String> {
        let decode = |text: &str| {
            let mut bytes = Vec::new();
            let mut rest = text.as_bytes();
            while let [first, tail @ ..] = rest {
                rest = tail;
                match first {
                    b'+' => bytes.push(b' '),
                    b'%' => {
                        let hex = std::str::from_utf8(&rest[..2]).unwrap();
                        bytes.push(u8::from_str_radix(hex, 16).unwrap());
                        rest = &rest[2..];
                    }
                    byte => bytes.push(*byte),
                }
            }
            String::from_utf8(bytes).unwrap()
        };
        body.split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(key, value)| (decode(key), decode(value)))
            .collect()
    }

    #[tokio::test]
    async fn test_calls_with_long_term_credentials() {
        let mock = MockEndpoint::start();
        let aws = mock.aws();

        let identity = aws.caller_identity().await.unwrap();
        let devices = aws.mfa_devices().await.unwrap();
        let code = "123456".parse().unwrap();
        let session = aws.session_token(&devices[0], &code, 7200).await.unwrap();

        assert_eq!(
            identity,
            Identity::from_arn("arn:aws:iam::111111111111:user/alice")
        );
        assert_eq!(devices, ["arn:aws:iam::111111111111:mfa/alice"]);
        assert_eq!(session.access_key_id, "ASIASESSION");
        assert_eq!(session.expiration, Some(at(1_800_000_000)));

        let requests = mock.requests();
        let calls: Vec<_> = requests
            .iter()
            .map(|r| (r.params["Action"].as_str(), r.signed_by.as_str()))
            .collect();
        assert_eq!(
            calls,
            [
                ("GetCallerIdentity", "AKIALONGTERM"),
                ("ListMFADevices", "AKIALONGTERM"),
                ("GetSessionToken", "AKIALONGTERM"),
            ]
        );
        let token = &requests[2].params;
        assert_eq!(token["SerialNumber"], "arn:aws:iam::111111111111:mfa/alice");
        assert_eq!(token["TokenCode"], "123456");
        assert_eq!(token["DurationSeconds"], "7200");
    }

    #[tokio::test]
    async fn test_assume_role_is_signed_with_the_session() {
        let mock = MockEndpoint::start();
        let session = SessionCredentials {
            access_key_id: "ASIASESSION".to_owned(),
            secret_access_key: "session-secret".to_owned(),
            session_token: "SESSIONTOKEN".to_owned(),
            expiration: None,
        };
        let role = RoleRequest {
            arn: ROLE_ARN.to_owned(),
            session_name: "alice".to_owned(),
            external_id: Some("partner-42".to_owned()),
            duration_secs: Some(7200),
            policy_arns: vec![
                "arn:aws:iam::aws:policy/ReadOnlyAccess".to_owned(),
                "arn:aws:iam::aws:policy/SecurityAudit".to_owned(),
            ],
            policy: Some(r#"{"Version":"2012-10-17"}"#.to_owned()),
        };

        let assumed = mock.aws().assume_role(&session, &role).await.unwrap();

        assert_eq!(assumed.credentials.access_key_id, "ASIAROLE");
        assert_eq!(
            assumed.identity.unwrap().prompt_label(),
            "AWS:AdminRole@222222222222"
        );
        let [request] = mock.requests().try_into().unwrap();
        assert_eq!(request.signed_by, "ASIASESSION");
        assert_eq!(request.session_token.as_deref(), Some("SESSIONTOKEN"));
        let params = &request.params;
        assert_eq!(params["RoleArn"], ROLE_ARN);
        assert_eq!(params["RoleSessionName"], "alice");
        assert_eq!(params["ExternalId"], "partner-42");
        assert_eq!(params["DurationSeconds"], "7200");
        assert_eq!(
            params["PolicyArns.member.1.arn"],
            "arn:aws:iam::aws:policy/ReadOnlyAccess"
        );
        assert_eq!(
            params["PolicyArns.member.2.arn"],
            "arn:aws:iam::aws:policy/SecurityAudit"
        );
        assert_eq!(params["Policy"], r#"{"Version":"2012-10-17"}"#);
    }

    #[tokio::test]
    async fn test_assume_role_sends_only_the_settings_given() {
        let mock = MockEndpoint::start();
        let role = RoleRequest::resolve(ROLE_ARN, |_| None).unwrap();

        mock.aws()
            .assume_role(&crate::session::tests::sample_credentials(), &role)
            .await
            .unwrap();

        let [request] = mock.requests().try_into().unwrap();
        let mut keys: Vec<_> = request.params.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["Action", "RoleArn", "RoleSessionName", "Version"]);
    }

    #[tokio::test]
    async fn test_service_error_from_the_endpoint() {
        let mock = MockEndpoint::start();
        let code = "000000".parse().unwrap();

        let error = mock
            .aws()
            .session_token("arn:aws:iam::111111111111:mfa/alice", &code, 3600)
            .await
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "AWS GetSessionToken failed: AccessDenied: MultiFactorAuthentication failed with \
             invalid MFA one time pass code."
        );
    }

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
