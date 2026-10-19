//! The flow of a run: get session credentials — reused or new — optionally
//! assume a role with them, and deliver the result to each requested output.

use std::io;
use std::time::{Duration, SystemTime};

use crate::aws::AwsApi;
use crate::config::{Config, ProfileTarget, SdkSettings};
use crate::credentials::{self, SessionProfile};
use crate::error::CliError;
use crate::mfa::{self, MfaCode};
use crate::profile;
use crate::role::RoleRequest;
use crate::session::{Session, SessionCredentials};
use crate::shell::{Shell, ShellLaunch};
use crate::terminal::Terminal;

/// A saved session is only reused while it has at least this long left, so a
/// reused session never ends sooner than the shortest one STS issues.
const MIN_REUSABLE: Duration = Duration::from_secs(15 * 60);

pub(crate) async fn run(
    config: &Config,
    aws: &impl AwsApi,
    terminal: &mut impl Terminal,
    now: SystemTime,
) -> Result<(), CliError> {
    // Resolved first, so a misconfigured role fails before an MFA code is spent.
    let role = role_request(config)?;
    let session = match reusable_session(config, now)? {
        Some((target, credentials)) => reuse(config, aws, terminal, target, credentials, now).await,
        None => renew(config, aws, terminal, now).await?,
    };
    let session = match &role {
        Some(role) => assume(aws, terminal, &session, role, now).await?,
        None => session,
    };
    deliver(config, terminal, &session)
}

/// The role to assume for `--role`.
fn role_request(config: &Config) -> Result<Option<RoleRequest>, CliError> {
    config
        .role
        .as_deref()
        .map(|role| RoleRequest::resolve(role, |key| profile_setting(config, role, key)))
        .transpose()
}

/// The `--update-profile` profile and its session, if the session is still
/// valid and `--force` was not passed. The file is read even with `--force`,
/// so one that could not be updated fails the run before an MFA code is spent.
fn reusable_session(
    config: &Config,
    now: SystemTime,
) -> Result<Option<(&ProfileTarget, SessionCredentials)>, CliError> {
    let Some(target) = &config.outputs.session_profile else {
        return Ok(None);
    };
    let doc = credentials::load(&target.file).map_err(|source| file_error(target, source))?;
    if config.force {
        return Ok(None);
    }
    Ok(credentials::find_session(&doc, &target.name)
        .filter(|session| {
            session
                .remaining(now)
                .is_some_and(|left| left >= MIN_REUSABLE)
        })
        .map(|session| (target, session)))
}

/// Use a saved session as it is. AWS is asked only who the caller is, to label
/// a shell prompt, so a failure there is not fatal.
async fn reuse(
    config: &Config,
    aws: &impl AwsApi,
    terminal: &mut impl Terminal,
    target: &ProfileTarget,
    credentials: SessionCredentials,
    now: SystemTime,
) -> Session {
    terminal.note(&format!(
        "Reusing profile '{}', valid until {}. Pass --force to renew it.",
        target.name,
        credentials.describe_validity(now)
    ));
    // With --role, the prompt shows the role instead.
    let identity = if config.outputs.shows_prompt() && config.role.is_none() {
        aws.caller_identity()
            .await
            .inspect_err(|error| terminal.note(&format!("Leaving the prompt unchanged: {error}")))
            .ok()
    } else {
        None
    };
    Session {
        credentials,
        identity,
    }
}

/// Request a new session, and save it to the `--update-profile` profile if
/// there is one.
async fn renew(
    config: &Config,
    aws: &impl AwsApi,
    terminal: &mut impl Terminal,
    now: SystemTime,
) -> Result<Session, CliError> {
    // Looking up the identity first proves the long-term credentials work
    // before the user is asked for an MFA code.
    let identity = aws.caller_identity().await?;
    let device = mfa_device(config, aws).await?;
    // Asking only now means a time-based code is as fresh as possible.
    let code = mfa_code(config, terminal)?;
    let credentials = aws
        .session_token(&device, &code, config.duration_secs)
        .await?;
    terminal.note(&format!(
        "New session valid until {}.",
        credentials.describe_validity(now)
    ));

    if let Some(target) = &config.outputs.session_profile {
        let region = aws.region().await;
        let profile = SessionProfile {
            name: &target.name,
            credentials: &credentials,
            region: region.as_deref(),
        };
        credentials::save(&target.file, &profile).map_err(|source| file_error(target, source))?;
        terminal.note(&format!(
            "Saved it to profile '{}' in {}.",
            target.name,
            target.file.display()
        ));
    }
    Ok(Session {
        credentials,
        identity: Some(identity),
    })
}

/// Assume `role` with the MFA session. No code is needed: the session carries
/// the MFA authentication that the role's trust policy checks.
async fn assume(
    aws: &impl AwsApi,
    terminal: &mut impl Terminal,
    session: &Session,
    role: &RoleRequest,
    now: SystemTime,
) -> Result<Session, CliError> {
    let assumed = aws.assume_role(&session.credentials, role).await?;
    terminal.note(&format!(
        "Assumed role {}, valid until {}.",
        role.arn,
        assumed.credentials.describe_validity(now)
    ));
    Ok(assumed)
}

/// The MFA device from `--arn`, else the profile's `mfa_serial`, else the
/// first usable device assigned to the user.
async fn mfa_device(config: &Config, aws: &impl AwsApi) -> Result<String, CliError> {
    if let Some(device) = &config.mfa_device {
        return Ok(device.clone());
    }
    if let Some(device) = profile_setting(config, &config.profile, "mfa_serial") {
        return Ok(device);
    }
    mfa::select_device(aws.mfa_devices().await?).ok_or(CliError::NoMfaDevice)
}

/// The MFA code from `--code`, else printed by the `--mfa-process` command or
/// the profile's `mfa_process`, else typed in by the user.
fn mfa_code(config: &Config, terminal: &mut impl Terminal) -> Result<MfaCode, CliError> {
    if let Some(code) = &config.code {
        return Ok(code.clone());
    }
    let command = config
        .mfa_process
        .clone()
        .or_else(|| profile_setting(config, &config.profile, "mfa_process"))
        .filter(|command| !command.trim().is_empty());
    match command {
        Some(command) => terminal
            .run_mfa_process(&command)?
            .parse()
            .map_err(|_| CliError::MfaProcessOutput),
        None => terminal.read_mfa_code(),
    }
}

/// A setting of `profile` in the shared AWS files.
fn profile_setting(config: &Config, profile: &str, key: &str) -> Option<String> {
    profile::setting(
        config.config_file.as_deref(),
        config.credentials_file.as_deref(),
        profile,
        key,
    )
}

fn file_error(target: &ProfileTarget, source: io::Error) -> CliError {
    CliError::CredentialsFile {
        path: target.file.clone(),
        source,
    }
}

/// Print the session for `--export`, then start the `--shell`.
fn deliver(
    config: &Config,
    terminal: &mut impl Terminal,
    session: &Session,
) -> Result<(), CliError> {
    let outputs = &config.outputs;
    if let Some(format) = outputs.export {
        terminal.print(&format.render(&session.credentials, session.identity.as_ref()))?;
    }
    if let Some(program) = &outputs.shell {
        terminal.run_shell(&shell_launch(&config.sdk, program, session))?;
    }
    Ok(())
}

fn shell_launch(sdk: &SdkSettings, program: &str, session: &Session) -> ShellLaunch {
    let mut env = session.credentials.env_vars();
    // The shell sees the same profile settings this run used.
    if let Some(profile) = &sdk.profile {
        env.push(("AWS_PROFILE", profile.clone()));
    }
    if let Some(file) = &sdk.credentials_file {
        env.push(("AWS_SHARED_CREDENTIALS_FILE", file.display().to_string()));
    }
    let prompt = session
        .identity
        .as_ref()
        .and_then(|id| Shell::detect(program).prompt_var(&id.prompt_label()));
    env.extend(prompt);
    ShellLaunch {
        program: program.to_owned(),
        env,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Env;
    use crate::config::tests::args;
    use crate::session::Identity;
    use crate::session::tests::{EXPIRATION_SECS, at, sample_credentials};
    use std::cell::RefCell;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;

    const ALICE_ARN: &str = "arn:aws:iam::123456789012:user/alice";
    const DEVICE: &str = "arn:aws:iam::123456789012:mfa/alice";
    const PROMPTED_CODE: &str = "654321";
    const ROLE_ARN: &str = "arn:aws:iam::222222222222:role/AdminRole";
    const ROLE_PROFILE: &str = "[profile dev-account]\n\
                                source_profile = mycompany-session\n\
                                role_arn = arn:aws:iam::222222222222:role/AdminRole\n";

    /// The fakes record each step here, so tests can assert ordering across
    /// AWS calls and terminal interaction.
    type Log = Rc<RefCell<Vec<String>>>;

    struct FakeAws {
        log: Log,
        devices: Vec<String>,
        identity_error: bool,
    }

    impl FakeAws {
        fn new(log: &Log) -> Self {
            Self {
                log: log.clone(),
                devices: vec![DEVICE.to_owned()],
                identity_error: false,
            }
        }

        fn record(&self, entry: String) {
            self.log.borrow_mut().push(entry);
        }
    }

    impl AwsApi for FakeAws {
        async fn caller_identity(&self) -> Result<Identity, CliError> {
            self.record("GetCallerIdentity".to_owned());
            if self.identity_error {
                return Err(CliError::Aws {
                    operation: "GetCallerIdentity",
                    message: "InvalidClientTokenId".to_owned(),
                });
            }
            Ok(Identity {
                account: "123456789012".to_owned(),
                arn: ALICE_ARN.to_owned(),
            })
        }

        async fn mfa_devices(&self) -> Result<Vec<String>, CliError> {
            self.record("ListMFADevices".to_owned());
            Ok(self.devices.clone())
        }

        async fn session_token(
            &self,
            mfa_device: &str,
            code: &MfaCode,
            duration_secs: i32,
        ) -> Result<SessionCredentials, CliError> {
            self.record(format!(
                "GetSessionToken {mfa_device} {code} {duration_secs}"
            ));
            Ok(sample_credentials())
        }

        async fn assume_role(
            &self,
            session: &SessionCredentials,
            role: &RoleRequest,
        ) -> Result<Session, CliError> {
            self.record(format!(
                "AssumeRole {} as {} with {}",
                role.arn, role.session_name, session.access_key_id
            ));
            let role_name = role.arn.rsplit('/').next().unwrap();
            Ok(Session {
                credentials: SessionCredentials {
                    access_key_id: "ASIAROLE".to_owned(),
                    ..sample_credentials()
                },
                identity: Some(Identity::from_arn(&format!(
                    "arn:aws:sts::222222222222:assumed-role/{role_name}/{}",
                    role.session_name
                ))),
            })
        }

        async fn region(&self) -> Option<String> {
            Some("eu-west-1".to_owned())
        }
    }

    #[derive(Default)]
    struct FakeTerminal {
        log: Log,
        stdout: String,
        notes: Vec<String>,
        shells: Vec<ShellLaunch>,
        /// What the `mfa_process` command prints.
        process_output: String,
    }

    impl FakeTerminal {
        fn new(log: &Log) -> Self {
            Self {
                log: log.clone(),
                ..Self::default()
            }
        }
    }

    impl Terminal for FakeTerminal {
        fn read_mfa_code(&mut self) -> Result<MfaCode, CliError> {
            self.log.borrow_mut().push("prompt".to_owned());
            Ok(PROMPTED_CODE.parse().unwrap())
        }

        fn run_mfa_process(&mut self, command: &str) -> Result<String, CliError> {
            self.log.borrow_mut().push(format!("mfa_process {command}"));
            Ok(self.process_output.clone())
        }

        fn print(&mut self, text: &str) -> Result<(), CliError> {
            self.log.borrow_mut().push("print".to_owned());
            self.stdout.push_str(text);
            Ok(())
        }

        fn note(&mut self, message: &str) {
            self.notes.push(message.to_owned());
        }

        fn run_shell(&mut self, launch: &ShellLaunch) -> Result<(), CliError> {
            self.log
                .borrow_mut()
                .push(format!("shell {}", launch.program));
            self.shells.push(launch.clone());
            Ok(())
        }
    }

    /// Runs the flow against the fakes, in a home directory with an empty
    /// `~/.aws`.
    struct Harness {
        home: tempfile::TempDir,
        env: Env,
        log: Log,
        aws: FakeAws,
        terminal: FakeTerminal,
    }

    impl Harness {
        fn new() -> Self {
            let home = tempfile::tempdir().unwrap();
            fs::create_dir(home.path().join(".aws")).unwrap();
            let env = Env {
                home_dir: Some(home.path().to_owned()),
                shell: Some("/bin/bash".to_owned()),
                ..Env::default()
            };
            let log = Log::default();
            Self {
                aws: FakeAws::new(&log),
                terminal: FakeTerminal::new(&log),
                home,
                env,
                log,
            }
        }

        fn aws_file(&self, name: &str) -> PathBuf {
            self.home.path().join(".aws").join(name)
        }

        fn write(&self, name: &str, contents: &str) {
            fs::write(self.aws_file(name), contents).unwrap();
        }

        fn read(&self, name: &str) -> String {
            fs::read_to_string(self.aws_file(name)).unwrap()
        }

        /// The AWS calls, prompts and outputs so far, in order.
        fn log(&self) -> Vec<String> {
            self.log.borrow().clone()
        }

        fn called(&self, prefix: &str) -> bool {
            self.log().iter().any(|entry| entry.starts_with(prefix))
        }

        /// Run with `arguments` while sample credentials have an hour left.
        async fn run(&mut self, arguments: &[&str]) -> Result<(), CliError> {
            self.run_with_left(arguments, Duration::from_secs(3600))
                .await
        }

        /// Run with `arguments` while sample credentials have `left` remaining.
        async fn run_with_left(
            &mut self,
            arguments: &[&str],
            left: Duration,
        ) -> Result<(), CliError> {
            let config = Config::new(args(arguments), &self.env).unwrap();
            let now = at(EXPIRATION_SECS) - left;
            super::run(&config, &self.aws, &mut self.terminal, now).await
        }
    }

    fn saved_session(name: &str, left_from: SystemTime) -> String {
        let credentials = SessionCredentials {
            access_key_id: "ASIASAVED".to_owned(),
            expiration: Some(left_from),
            ..sample_credentials()
        };
        SessionProfile {
            name,
            credentials: &credentials,
            region: None,
        }
        .section()
    }

    #[tokio::test]
    async fn test_export_with_code() {
        let mut t = Harness::new();

        t.run(&["-e", "-c", "123456"]).await.unwrap();

        assert_eq!(
            t.log(),
            [
                "GetCallerIdentity",
                "ListMFADevices",
                &format!("GetSessionToken {DEVICE} 123456 3600"),
                "print",
            ]
        );
        assert_eq!(
            t.terminal.stdout,
            "export AWS_ACCESS_KEY_ID='ASIATEST'\n\
             export AWS_SECRET_ACCESS_KEY='secret'\n\
             export AWS_SESSION_TOKEN='token'\n\
             export AWS_CREDENTIAL_EXPIRATION='2027-01-15T08:00:00Z'\n\
             export PS1='AWS:alice@123456789012 \\$ '\n"
        );
        assert_eq!(
            t.terminal.notes,
            ["New session valid until 2027-01-15T08:00:00Z (1h 00m left)."]
        );
    }

    #[tokio::test]
    async fn test_prompts_for_code_after_checking_credentials() {
        let mut t = Harness::new();

        t.run(&["-e", "-d", "7200"]).await.unwrap();

        assert_eq!(
            t.log(),
            [
                "GetCallerIdentity",
                "ListMFADevices",
                "prompt",
                &format!("GetSessionToken {DEVICE} {PROMPTED_CODE} 7200"),
                "print",
            ]
        );
    }

    #[tokio::test]
    async fn test_invalid_credentials_fail_before_prompting() {
        let mut t = Harness::new();
        t.aws.identity_error = true;

        let error = t.run(&["-u", "session"]).await.unwrap_err();

        assert!(matches!(
            error,
            CliError::Aws {
                operation: "GetCallerIdentity",
                ..
            }
        ));
        assert_eq!(t.log(), ["GetCallerIdentity"]);
        assert!(!t.aws_file("credentials").exists());
    }

    #[tokio::test]
    async fn test_arn_skips_device_lookup() {
        let mut t = Harness::new();

        t.run(&["-e", "-c", "123456", "-a", "GAHT1234"])
            .await
            .unwrap();

        assert_eq!(
            t.log(),
            [
                "GetCallerIdentity",
                "GetSessionToken GAHT1234 123456 3600",
                "print"
            ]
        );
    }

    #[tokio::test]
    async fn test_profile_mfa_serial_skips_device_lookup() {
        let mut t = Harness::new();
        t.write(
            "config",
            "[profile dev]\nmfa_serial = arn:aws:iam::1:mfa/dev\n",
        );

        t.run(&["-e", "-c", "123456", "-p", "dev"]).await.unwrap();

        assert_eq!(
            t.log(),
            [
                "GetCallerIdentity",
                "GetSessionToken arn:aws:iam::1:mfa/dev 123456 3600",
                "print",
            ]
        );
    }

    #[tokio::test]
    async fn test_aws_profile_env_selects_mfa_serial() {
        let mut t = Harness::new();
        t.write(
            "config",
            "[profile dev]\nmfa_serial = arn:aws:iam::1:mfa/dev\n",
        );
        t.env.aws_profile = Some("dev".to_owned());

        t.run(&["-e", "-c", "123456"]).await.unwrap();

        assert!(t.called("GetSessionToken arn:aws:iam::1:mfa/dev 123456 3600"));
    }

    #[tokio::test]
    async fn test_mfa_process_from_profile() {
        let mut t = Harness::new();
        t.write(
            "config",
            "[profile dev]\nmfa_process = ykman oath accounts code --single aws\n",
        );
        t.terminal.process_output = "111222\n".to_owned();

        t.run(&["-e", "-p", "dev"]).await.unwrap();

        assert_eq!(
            t.log(),
            [
                "GetCallerIdentity",
                "ListMFADevices",
                "mfa_process ykman oath accounts code --single aws",
                &format!("GetSessionToken {DEVICE} 111222 3600"),
                "print",
            ]
        );
    }

    #[tokio::test]
    async fn test_mfa_process_flag_wins_over_profile() {
        let mut t = Harness::new();
        t.write("config", "[default]\nmfa_process = pass otp aws\n");
        t.terminal.process_output = "111222".to_owned();

        t.run(&["-e", "--mfa-process", "op item get aws --otp"])
            .await
            .unwrap();

        assert!(t.called("mfa_process op item get aws --otp"));
        assert!(!t.called("mfa_process pass"));
    }

    #[tokio::test]
    async fn test_code_wins_over_mfa_process() {
        let mut t = Harness::new();
        t.write("config", "[default]\nmfa_process = pass otp aws\n");

        t.run(&["-e", "-c", "123456"]).await.unwrap();

        assert!(!t.called("mfa_process"));
        assert!(t.called(&format!("GetSessionToken {DEVICE} 123456")));
    }

    #[tokio::test]
    async fn test_empty_mfa_process_prompts() {
        let mut t = Harness::new();
        t.write("config", "[default]\nmfa_process =\n");

        t.run(&["-e"]).await.unwrap();

        assert!(!t.called("mfa_process"));
        assert!(t.called("prompt"));
    }

    #[tokio::test]
    async fn test_mfa_process_must_print_only_a_code() {
        let mut t = Harness::new();
        // `ykman oath accounts code` without --single also prints the name.
        t.terminal.process_output = "aws  123456\n".to_owned();

        let error = t
            .run(&["-e", "--mfa-process", "ykman oath accounts code aws"])
            .await
            .unwrap_err();

        assert!(matches!(error, CliError::MfaProcessOutput), "{error:?}");
        assert!(!t.called("GetSessionToken"));
    }

    #[tokio::test]
    async fn test_no_usable_mfa_device() {
        let mut t = Harness::new();
        t.aws.devices = vec!["arn:aws:iam::1:u2f/user/alice/key".to_owned()];

        let error = t.run(&["-e"]).await.unwrap_err();

        assert!(matches!(error, CliError::NoMfaDevice));
        assert!(!t.called("prompt"));
    }

    #[tokio::test]
    async fn test_update_profile_saves_session() {
        let mut t = Harness::new();
        t.write("credentials", "[default]\naws_access_key_id = LONGTERM\n");

        t.run(&["-u", "session", "-c", "123456"]).await.unwrap();

        assert_eq!(
            t.read("credentials"),
            "[default]\naws_access_key_id = LONGTERM\n\n\
             [session]\n\
             aws_access_key_id = ASIATEST\n\
             aws_secret_access_key = secret\n\
             aws_session_token = token\n\
             region = eu-west-1\n\
             expiration = 2027-01-15T08:00:00Z\n"
        );
        assert_eq!(
            t.terminal.notes[1],
            format!(
                "Saved it to profile 'session' in {}.",
                t.aws_file("credentials").display()
            )
        );
        assert!(t.terminal.stdout.is_empty());
    }

    #[tokio::test]
    async fn test_unparsable_credentials_file_fails_before_aws() {
        // A file that cannot be updated must not cost an MFA code.
        let invalid = "aws_access_key_id = outside any profile\n";
        for arguments in [&["-u", "session"][..], &["-u", "session", "--force"]] {
            let mut t = Harness::new();
            t.write("credentials", invalid);

            let error = t.run(arguments).await.unwrap_err();

            assert!(
                matches!(error, CliError::CredentialsFile { .. }),
                "{arguments:?}: {error:?}"
            );
            assert!(t.log().is_empty(), "{arguments:?}: {:?}", t.log());
            assert_eq!(t.read("credentials"), invalid);
        }
    }

    #[tokio::test]
    async fn test_valid_profile_is_reused_without_aws() {
        let mut t = Harness::new();
        let saved = saved_session("session", at(EXPIRATION_SECS));
        t.write("credentials", &saved);

        t.run_with_left(&["-u", "session"], Duration::from_secs(2 * 3600))
            .await
            .unwrap();

        assert!(t.log().is_empty(), "no AWS calls and no prompt");
        assert_eq!(t.read("credentials"), saved, "the file is untouched");
        assert_eq!(
            t.terminal.notes,
            [
                "Reusing profile 'session', valid until 2027-01-15T08:00:00Z (2h 00m left). \
              Pass --force to renew it."
            ]
        );
    }

    #[tokio::test]
    async fn test_reused_profile_exports_json_without_aws() {
        let mut t = Harness::new();
        t.write(
            "credentials",
            &saved_session("session", at(EXPIRATION_SECS)),
        );

        t.run(&["-u", "session", "-e", "--format", "json"])
            .await
            .unwrap();

        assert_eq!(t.log(), ["print"], "JSON needs no identity");
        assert!(t.terminal.stdout.contains("\"AccessKeyId\": \"ASIASAVED\""));
    }

    #[tokio::test]
    async fn test_reused_profile_looks_up_identity_for_prompt() {
        let mut t = Harness::new();
        t.write(
            "credentials",
            &saved_session("session", at(EXPIRATION_SECS)),
        );

        t.run(&["-u", "session", "-e"]).await.unwrap();

        assert_eq!(t.log(), ["GetCallerIdentity", "print"]);
        assert!(
            t.terminal
                .stdout
                .contains("export AWS_ACCESS_KEY_ID='ASIASAVED'\n")
        );
        assert!(t.terminal.stdout.contains("PS1='AWS:alice@123456789012"));
    }

    #[tokio::test]
    async fn test_reused_profile_survives_identity_failure() {
        let mut t = Harness::new();
        t.write(
            "credentials",
            &saved_session("session", at(EXPIRATION_SECS)),
        );
        t.aws.identity_error = true;

        t.run(&["-u", "session", "-e"]).await.unwrap();

        assert!(
            t.terminal
                .stdout
                .contains("export AWS_ACCESS_KEY_ID='ASIASAVED'\n")
        );
        assert!(
            !t.terminal.stdout.contains("PS1"),
            "no identity, no prompt label"
        );
        assert!(t.terminal.notes[1].starts_with("Leaving the prompt unchanged: "));
    }

    #[tokio::test]
    async fn test_profile_close_to_expiry_is_renewed() {
        let mut t = Harness::new();
        t.write(
            "credentials",
            &saved_session("session", at(EXPIRATION_SECS)),
        );

        t.run_with_left(
            &["-u", "session", "-c", "123456"],
            MIN_REUSABLE - Duration::from_secs(1),
        )
        .await
        .unwrap();

        assert!(t.called("GetSessionToken"));
        assert!(
            t.read("credentials")
                .contains("aws_access_key_id = ASIATEST")
        );
    }

    #[tokio::test]
    async fn test_profile_without_expiration_is_renewed() {
        // Profiles written by earlier versions have no expiration recorded.
        let mut t = Harness::new();
        t.write(
            "credentials",
            "[session]\naws_access_key_id = OLD\naws_secret_access_key = OLD\naws_session_token = OLD\n",
        );

        t.run(&["-u", "session", "-c", "123456"]).await.unwrap();

        assert!(t.called("GetSessionToken"));
        assert!(!t.read("credentials").contains("OLD"));
    }

    #[tokio::test]
    async fn test_force_renews_valid_profile() {
        let mut t = Harness::new();
        t.write(
            "credentials",
            &saved_session("session", at(EXPIRATION_SECS)),
        );

        t.run(&["-u", "session", "--force", "-c", "123456"])
            .await
            .unwrap();

        assert!(t.called("GetSessionToken"));
        assert!(!t.read("credentials").contains("ASIASAVED"));
    }

    #[tokio::test]
    async fn test_role_with_new_session() {
        let mut t = Harness::new();
        t.write("config", ROLE_PROFILE);

        t.run(&["-e", "-c", "123456", "--role", "dev-account"])
            .await
            .unwrap();

        assert_eq!(
            t.log(),
            [
                "GetCallerIdentity",
                "ListMFADevices",
                &format!("GetSessionToken {DEVICE} 123456 3600"),
                &format!("AssumeRole {ROLE_ARN} as aws-mfa-session with ASIATEST"),
                "print",
            ]
        );
        assert!(
            t.terminal
                .stdout
                .contains("export AWS_ACCESS_KEY_ID='ASIAROLE'\n")
        );
        assert!(
            t.terminal
                .stdout
                .ends_with("export PS1='AWS:AdminRole@222222222222 \\$ '\n"),
            "the prompt shows the role: {}",
            t.terminal.stdout
        );
        assert_eq!(
            t.terminal.notes[1],
            format!("Assumed role {ROLE_ARN}, valid until 2027-01-15T08:00:00Z (1h 00m left).")
        );
    }

    #[tokio::test]
    async fn test_role_with_reused_session_needs_no_code() {
        let mut t = Harness::new();
        t.write(
            "credentials",
            &saved_session("session", at(EXPIRATION_SECS)),
        );

        t.run(&["-u", "session", "-e", "--role", ROLE_ARN])
            .await
            .unwrap();

        assert_eq!(
            t.log(),
            [
                &format!("AssumeRole {ROLE_ARN} as aws-mfa-session with ASIASAVED"),
                "print",
            ],
            "no identity lookup, no prompt, no GetSessionToken"
        );
    }

    #[tokio::test]
    async fn test_role_keeps_the_mfa_session_in_update_profile() {
        let mut t = Harness::new();

        t.run(&["-u", "session", "-s", "-c", "123456", "--role", ROLE_ARN])
            .await
            .unwrap();

        let saved = t.read("credentials");
        assert!(saved.contains("aws_access_key_id = ASIATEST"), "{saved}");
        let [launch] = t.terminal.shells.as_slice() else {
            panic!("expected one shell launch");
        };
        assert_eq!(launch.env[0], ("AWS_ACCESS_KEY_ID", "ASIAROLE".to_owned()));
    }

    #[tokio::test]
    async fn test_role_profile_settings_are_used() {
        let mut t = Harness::new();
        t.write(
            "config",
            &format!("{ROLE_PROFILE}role_session_name = alice\n"),
        );

        t.run(&["-e", "-c", "123456", "--role", "dev-account"])
            .await
            .unwrap();

        assert!(t.called(&format!("AssumeRole {ROLE_ARN} as alice with")));
    }

    #[tokio::test]
    async fn test_role_without_role_arn_fails_before_aws() {
        let mut t = Harness::new();
        t.write("config", "[profile dev-account]\nregion = eu-west-1\n");

        let error = t.run(&["-e", "--role", "dev-account"]).await.unwrap_err();

        assert!(matches!(error, CliError::NoRoleArn { .. }), "{error:?}");
        assert!(t.log().is_empty(), "{:?}", t.log());
    }

    #[tokio::test]
    async fn test_shell_launch() {
        let mut t = Harness::new();

        t.run(&["-s", "-c", "123456", "-p", "dev", "-f", "/tmp/creds"])
            .await
            .unwrap();

        let [launch] = t.terminal.shells.as_slice() else {
            panic!("expected one shell launch");
        };
        assert_eq!(launch.program, "/bin/bash");
        let env: Vec<(&str, &str)> = launch.env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!(
            env,
            [
                ("AWS_ACCESS_KEY_ID", "ASIATEST"),
                ("AWS_SECRET_ACCESS_KEY", "secret"),
                ("AWS_SESSION_TOKEN", "token"),
                ("AWS_CREDENTIAL_EXPIRATION", "2027-01-15T08:00:00Z"),
                ("AWS_PROFILE", "dev"),
                (
                    "AWS_SHARED_CREDENTIALS_FILE",
                    Path::new("/tmp/creds").to_str().unwrap()
                ),
                ("PS1", "AWS:alice@123456789012 \\$ "),
            ]
        );
    }

    #[tokio::test]
    async fn test_export_happens_before_shell() {
        let mut t = Harness::new();

        t.run(&["-s", "-e", "-c", "123456"]).await.unwrap();

        let log = t.log();
        assert_eq!(log[log.len() - 2..], ["print", "shell /bin/bash"]);
    }
}
