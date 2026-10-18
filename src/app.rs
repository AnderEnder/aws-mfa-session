//! The flow of a run: get session credentials — reused or new — and deliver
//! them to each requested output.

use std::time::{Duration, SystemTime};

use crate::aws::AwsApi;
use crate::config::{Config, ProfileTarget};
use crate::credentials::{self, SessionProfile};
use crate::error::CliError;
use crate::mfa;
use crate::profile;
use crate::session::{Identity, SessionCredentials};
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
    let outputs = &config.outputs;
    let reusable = reusable_session(config, now)?;
    if let Some((target, credentials)) = &reusable {
        terminal.note(&format!(
            "Reusing profile '{}', valid until {}. Pass --force to renew it.",
            target.name,
            credentials.describe_validity(now)
        ));
    }

    // For a new session, looking up the identity first proves the long-term
    // credentials work before the user is asked for an MFA code. A reused
    // session only needs it to label the prompt, so a failure is not fatal.
    let identity = match &reusable {
        None => Some(aws.caller_identity().await?),
        Some(_) if outputs.shows_prompt() => aws
            .caller_identity()
            .await
            .inspect_err(|error| terminal.note(&format!("Leaving the prompt unchanged: {error}")))
            .ok(),
        Some(_) => None,
    };

    let credentials = match reusable {
        Some((_, credentials)) => credentials,
        None => {
            let credentials = new_session(config, aws, terminal).await?;
            terminal.note(&format!(
                "New session valid until {}.",
                credentials.describe_validity(now)
            ));
            if let Some(target) = &outputs.session_profile {
                save_profile(target, &credentials, aws.region().await.as_deref())?;
                terminal.note(&format!(
                    "Saved it to profile '{}' in {}.",
                    target.name,
                    target.file.display()
                ));
            }
            credentials
        }
    };

    if let Some(format) = outputs.export {
        terminal.print(&format.render(&credentials, identity.as_ref()))?;
    }
    if let Some(program) = &outputs.shell {
        terminal.run_shell(&shell_launch(
            config,
            program,
            &credentials,
            identity.as_ref(),
        ))?;
    }
    Ok(())
}

/// The `--update-profile` profile and its session, if the session is still
/// valid and `--force` was not passed.
fn reusable_session(
    config: &Config,
    now: SystemTime,
) -> Result<Option<(&ProfileTarget, SessionCredentials)>, CliError> {
    let Some(target) = &config.outputs.session_profile else {
        return Ok(None);
    };
    if config.force {
        return Ok(None);
    }
    let contents = credentials::read(&target.file).map_err(|source| CliError::CredentialsFile {
        path: target.file.clone(),
        source,
    })?;
    Ok(credentials::find_session(&contents, &target.name)
        .filter(|session| {
            session
                .remaining(now)
                .is_some_and(|left| left >= MIN_REUSABLE)
        })
        .map(|session| (target, session)))
}

async fn new_session(
    config: &Config,
    aws: &impl AwsApi,
    terminal: &mut impl Terminal,
) -> Result<SessionCredentials, CliError> {
    let device = mfa_device(config, aws).await?;
    // Asking only now means a time-based code is as fresh as possible.
    let code = match &config.code {
        Some(code) => code.clone(),
        None => terminal.read_mfa_code()?,
    };
    aws.session_token(&device, &code, config.duration_secs)
        .await
}

/// The MFA device from `--arn`, else the profile's `mfa_serial`, else the
/// first usable device assigned to the user.
async fn mfa_device(config: &Config, aws: &impl AwsApi) -> Result<String, CliError> {
    if let Some(device) = &config.mfa_device {
        return Ok(device.clone());
    }
    let configured = profile::mfa_serial(
        config.config_file(),
        config.credentials_file(),
        &config.profile,
    );
    if let Some(device) = configured {
        return Ok(device);
    }
    mfa::select_device(aws.mfa_devices().await?).ok_or(CliError::NoMfaDevice)
}

fn save_profile(
    target: &ProfileTarget,
    credentials: &SessionCredentials,
    region: Option<&str>,
) -> Result<(), CliError> {
    let profile = SessionProfile {
        name: &target.name,
        credentials,
        region,
    };
    credentials::save(&target.file, &profile).map_err(|source| CliError::CredentialsFile {
        path: target.file.clone(),
        source,
    })
}

fn shell_launch(
    config: &Config,
    program: &str,
    credentials: &SessionCredentials,
    identity: Option<&Identity>,
) -> ShellLaunch {
    let mut env = credentials.env_vars();
    // The shell sees the same profile settings this run used.
    if let Some(profile) = &config.sdk.profile {
        env.push(("AWS_PROFILE", profile.clone()));
    }
    if let Some(file) = &config.sdk.credentials_file {
        env.push(("AWS_SHARED_CREDENTIALS_FILE", file.display().to_string()));
    }
    let prompt = identity.and_then(|id| Shell::detect(program).prompt_var(&id.prompt_label()));
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
    use crate::mfa::MfaCode;
    use crate::session::tests::{EXPIRATION_SECS, at, sample_credentials};
    use std::cell::RefCell;
    use std::fs;
    use std::path::Path;
    use std::rc::Rc;

    const ALICE_ARN: &str = "arn:aws:iam::123456789012:user/alice";
    const DEVICE: &str = "arn:aws:iam::123456789012:mfa/alice";
    const PROMPTED_CODE: &str = "654321";

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
            self.shells.push(ShellLaunch {
                program: launch.program.clone(),
                env: launch.env.clone(),
            });
            Ok(())
        }
    }

    /// An isolated home directory with empty AWS files.
    struct Home {
        dir: tempfile::TempDir,
    }

    impl Home {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            fs::create_dir(dir.path().join(".aws")).unwrap();
            Self { dir }
        }

        fn env(&self) -> Env {
            Env {
                home_dir: Some(self.dir.path().to_owned()),
                shell: Some("/bin/bash".to_owned()),
                ..Env::default()
            }
        }

        fn aws_file(&self, name: &str) -> std::path::PathBuf {
            self.dir.path().join(".aws").join(name)
        }

        fn write(&self, name: &str, contents: &str) {
            fs::write(self.aws_file(name), contents).unwrap();
        }

        fn read(&self, name: &str) -> String {
            fs::read_to_string(self.aws_file(name)).unwrap()
        }

        fn config(&self, arguments: &[&str]) -> Config {
            Config::new(args(arguments), &self.env()).unwrap()
        }
    }

    /// Run the flow at a time when sample credentials have `left` remaining.
    async fn run_with_left(
        config: &Config,
        aws: &FakeAws,
        terminal: &mut FakeTerminal,
        left: Duration,
    ) -> Result<(), CliError> {
        let now = at(EXPIRATION_SECS) - left;
        run(config, aws, terminal, now).await
    }

    async fn run_at_start(
        config: &Config,
        aws: &FakeAws,
        terminal: &mut FakeTerminal,
    ) -> Result<(), CliError> {
        run_with_left(config, aws, terminal, Duration::from_secs(3600)).await
    }

    fn log_entries(log: &Log) -> Vec<String> {
        log.borrow().clone()
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
        let home = Home::new();
        let log = Log::default();
        let (aws, mut terminal) = (FakeAws::new(&log), FakeTerminal::new(&log));
        let config = home.config(&["-e", "-c", "123456"]);

        run_at_start(&config, &aws, &mut terminal).await.unwrap();

        assert_eq!(
            log_entries(&log),
            [
                "GetCallerIdentity",
                "ListMFADevices",
                &format!("GetSessionToken {DEVICE} 123456 3600"),
                "print",
            ]
        );
        assert_eq!(
            terminal.stdout,
            "export AWS_ACCESS_KEY_ID='ASIATEST'\n\
             export AWS_SECRET_ACCESS_KEY='secret'\n\
             export AWS_SESSION_TOKEN='token'\n\
             export AWS_CREDENTIAL_EXPIRATION='2027-01-15T08:00:00Z'\n\
             export PS1='AWS:alice@123456789012 \\$ '\n"
        );
        assert_eq!(
            terminal.notes,
            ["New session valid until 2027-01-15T08:00:00Z (1h 00m left)."]
        );
    }

    #[tokio::test]
    async fn test_prompts_for_code_after_checking_credentials() {
        let home = Home::new();
        let log = Log::default();
        let (aws, mut terminal) = (FakeAws::new(&log), FakeTerminal::new(&log));
        let config = home.config(&["-e", "-d", "7200"]);

        run_at_start(&config, &aws, &mut terminal).await.unwrap();

        assert_eq!(
            log_entries(&log),
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
        let home = Home::new();
        let log = Log::default();
        let aws = FakeAws {
            identity_error: true,
            ..FakeAws::new(&log)
        };
        let mut terminal = FakeTerminal::new(&log);
        let config = home.config(&["-u", "session"]);

        let error = run_at_start(&config, &aws, &mut terminal)
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            CliError::Aws {
                operation: "GetCallerIdentity",
                ..
            }
        ));
        assert_eq!(log_entries(&log), ["GetCallerIdentity"]);
        assert!(!home.aws_file("credentials").exists());
    }

    #[tokio::test]
    async fn test_arn_skips_device_lookup() {
        let home = Home::new();
        let log = Log::default();
        let (aws, mut terminal) = (FakeAws::new(&log), FakeTerminal::new(&log));
        let config = home.config(&["-e", "-c", "123456", "-a", "GAHT1234"]);

        run_at_start(&config, &aws, &mut terminal).await.unwrap();

        assert_eq!(
            log_entries(&log),
            [
                "GetCallerIdentity",
                "GetSessionToken GAHT1234 123456 3600",
                "print"
            ]
        );
    }

    #[tokio::test]
    async fn test_profile_mfa_serial_skips_device_lookup() {
        let home = Home::new();
        home.write(
            "config",
            "[profile dev]\nmfa_serial = arn:aws:iam::1:mfa/dev\n",
        );
        let log = Log::default();
        let (aws, mut terminal) = (FakeAws::new(&log), FakeTerminal::new(&log));
        let config = home.config(&["-e", "-c", "123456", "-p", "dev"]);

        run_at_start(&config, &aws, &mut terminal).await.unwrap();

        assert_eq!(
            log_entries(&log),
            [
                "GetCallerIdentity",
                "GetSessionToken arn:aws:iam::1:mfa/dev 123456 3600",
                "print",
            ]
        );
    }

    #[tokio::test]
    async fn test_aws_profile_env_selects_mfa_serial() {
        let home = Home::new();
        home.write(
            "config",
            "[profile dev]\nmfa_serial = arn:aws:iam::1:mfa/dev\n",
        );
        let log = Log::default();
        let (aws, mut terminal) = (FakeAws::new(&log), FakeTerminal::new(&log));
        let env = Env {
            aws_profile: Some("dev".to_owned()),
            ..home.env()
        };
        let config = Config::new(args(&["-e", "-c", "123456"]), &env).unwrap();

        run_at_start(&config, &aws, &mut terminal).await.unwrap();

        assert!(
            log_entries(&log)
                .contains(&"GetSessionToken arn:aws:iam::1:mfa/dev 123456 3600".to_owned())
        );
    }

    #[tokio::test]
    async fn test_no_usable_mfa_device() {
        let home = Home::new();
        let log = Log::default();
        let aws = FakeAws {
            devices: vec!["arn:aws:iam::1:u2f/user/alice/key".to_owned()],
            ..FakeAws::new(&log)
        };
        let mut terminal = FakeTerminal::new(&log);
        let config = home.config(&["-e"]);

        let error = run_at_start(&config, &aws, &mut terminal)
            .await
            .unwrap_err();

        assert!(matches!(error, CliError::NoMfaDevice));
        assert!(!log_entries(&log).contains(&"prompt".to_owned()));
    }

    #[tokio::test]
    async fn test_update_profile_saves_session() {
        let home = Home::new();
        home.write("credentials", "[default]\naws_access_key_id = LONGTERM\n");
        let log = Log::default();
        let (aws, mut terminal) = (FakeAws::new(&log), FakeTerminal::new(&log));
        let config = home.config(&["-u", "session", "-c", "123456"]);

        run_at_start(&config, &aws, &mut terminal).await.unwrap();

        assert_eq!(
            home.read("credentials"),
            "[default]\naws_access_key_id = LONGTERM\n\n\
             [session]\n\
             aws_access_key_id = ASIATEST\n\
             aws_secret_access_key = secret\n\
             aws_session_token = token\n\
             region = eu-west-1\n\
             expiration = 2027-01-15T08:00:00Z\n"
        );
        assert_eq!(
            terminal.notes[1],
            format!(
                "Saved it to profile 'session' in {}.",
                home.aws_file("credentials").display()
            )
        );
        assert!(terminal.stdout.is_empty());
    }

    #[tokio::test]
    async fn test_valid_profile_is_reused_without_aws() {
        let home = Home::new();
        let saved = saved_session("session", at(EXPIRATION_SECS));
        home.write("credentials", &saved);
        let log = Log::default();
        let (aws, mut terminal) = (FakeAws::new(&log), FakeTerminal::new(&log));
        let config = home.config(&["-u", "session"]);

        run_with_left(&config, &aws, &mut terminal, Duration::from_secs(2 * 3600))
            .await
            .unwrap();

        assert!(log_entries(&log).is_empty(), "no AWS calls and no prompt");
        assert_eq!(home.read("credentials"), saved, "the file is untouched");
        assert_eq!(
            terminal.notes,
            [
                "Reusing profile 'session', valid until 2027-01-15T08:00:00Z (2h 00m left). \
              Pass --force to renew it."
            ]
        );
    }

    #[tokio::test]
    async fn test_reused_profile_feeds_other_outputs() {
        let home = Home::new();
        home.write(
            "credentials",
            &saved_session("session", at(EXPIRATION_SECS)),
        );
        let log = Log::default();
        let (aws, mut terminal) = (FakeAws::new(&log), FakeTerminal::new(&log));

        let json = home.config(&["-u", "session", "-e", "--format", "json"]);
        run_at_start(&json, &aws, &mut terminal).await.unwrap();
        assert_eq!(log_entries(&log), ["print"], "JSON needs no identity");
        assert!(terminal.stdout.contains("\"AccessKeyId\": \"ASIASAVED\""));

        let bash = home.config(&["-u", "session", "-e"]);
        let mut terminal = FakeTerminal::new(&log);
        log.borrow_mut().clear();
        run_at_start(&bash, &aws, &mut terminal).await.unwrap();
        assert_eq!(
            log_entries(&log),
            ["GetCallerIdentity", "print"],
            "the prompt needs it"
        );
        assert!(
            terminal
                .stdout
                .contains("export AWS_ACCESS_KEY_ID='ASIASAVED'\n")
        );
    }

    #[tokio::test]
    async fn test_reused_profile_survives_identity_failure() {
        let home = Home::new();
        home.write(
            "credentials",
            &saved_session("session", at(EXPIRATION_SECS)),
        );
        let log = Log::default();
        let aws = FakeAws {
            identity_error: true,
            ..FakeAws::new(&log)
        };
        let mut terminal = FakeTerminal::new(&log);
        let config = home.config(&["-u", "session", "-e"]);

        run_at_start(&config, &aws, &mut terminal).await.unwrap();

        assert!(
            terminal
                .stdout
                .contains("export AWS_ACCESS_KEY_ID='ASIASAVED'\n")
        );
        assert!(
            !terminal.stdout.contains("PS1"),
            "no identity, no prompt label"
        );
        assert!(terminal.notes[1].starts_with("Leaving the prompt unchanged: "));
    }

    #[tokio::test]
    async fn test_profile_close_to_expiry_is_renewed() {
        let home = Home::new();
        home.write(
            "credentials",
            &saved_session("session", at(EXPIRATION_SECS)),
        );
        let log = Log::default();
        let (aws, mut terminal) = (FakeAws::new(&log), FakeTerminal::new(&log));
        let config = home.config(&["-u", "session", "-c", "123456"]);

        run_with_left(
            &config,
            &aws,
            &mut terminal,
            MIN_REUSABLE - Duration::from_secs(1),
        )
        .await
        .unwrap();

        assert!(
            log_entries(&log)
                .iter()
                .any(|e| e.starts_with("GetSessionToken"))
        );
        assert!(
            home.read("credentials")
                .contains("aws_access_key_id = ASIATEST")
        );
    }

    #[tokio::test]
    async fn test_profile_without_expiration_is_renewed() {
        // Profiles written by earlier versions have no expiration recorded.
        let home = Home::new();
        home.write(
            "credentials",
            "[session]\naws_access_key_id = OLD\naws_secret_access_key = OLD\naws_session_token = OLD\n",
        );
        let log = Log::default();
        let (aws, mut terminal) = (FakeAws::new(&log), FakeTerminal::new(&log));
        let config = home.config(&["-u", "session", "-c", "123456"]);

        run_at_start(&config, &aws, &mut terminal).await.unwrap();

        assert!(
            log_entries(&log)
                .iter()
                .any(|e| e.starts_with("GetSessionToken"))
        );
        assert!(!home.read("credentials").contains("OLD"));
    }

    #[tokio::test]
    async fn test_force_renews_valid_profile() {
        let home = Home::new();
        home.write(
            "credentials",
            &saved_session("session", at(EXPIRATION_SECS)),
        );
        let log = Log::default();
        let (aws, mut terminal) = (FakeAws::new(&log), FakeTerminal::new(&log));
        let config = home.config(&["-u", "session", "--force", "-c", "123456"]);

        run_at_start(&config, &aws, &mut terminal).await.unwrap();

        assert!(
            log_entries(&log)
                .iter()
                .any(|e| e.starts_with("GetSessionToken"))
        );
        assert!(!home.read("credentials").contains("ASIASAVED"));
    }

    #[tokio::test]
    async fn test_shell_launch() {
        let home = Home::new();
        let log = Log::default();
        let (aws, mut terminal) = (FakeAws::new(&log), FakeTerminal::new(&log));
        let config = home.config(&["-s", "-c", "123456", "-p", "dev", "-f", "/tmp/creds"]);

        run_at_start(&config, &aws, &mut terminal).await.unwrap();

        let [launch] = terminal.shells.as_slice() else {
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
        let home = Home::new();
        let log = Log::default();
        let (aws, mut terminal) = (FakeAws::new(&log), FakeTerminal::new(&log));
        let config = home.config(&["-s", "-e", "-c", "123456"]);

        run_at_start(&config, &aws, &mut terminal).await.unwrap();

        let entries = log_entries(&log);
        assert_eq!(entries[entries.len() - 2..], ["print", "shell /bin/bash"]);
    }
}
