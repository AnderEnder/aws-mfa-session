//! Resolves command-line arguments and environment variables into the settings
//! for a run, so that nothing else reads (or writes) process-wide state.

use std::path::{Path, PathBuf};

use crate::args::Args;
use crate::error::CliError;
use crate::export::ExportFormat;
use crate::mfa::MfaCode;
use crate::shell::Shell;

#[cfg(not(windows))]
const DEFAULT_SHELL: &str = "/bin/sh";

#[cfg(windows)]
const DEFAULT_SHELL: &str = "cmd.exe";

const DEFAULT_PROFILE: &str = "default";

/// The environment the tool consults, captured once at startup.
#[derive(Clone, Debug, Default)]
pub struct Env {
    pub aws_profile: Option<String>,
    pub aws_config_file: Option<String>,
    pub aws_shared_credentials_file: Option<String>,
    pub shell: Option<String>,
    pub home_dir: Option<PathBuf>,
}

impl Env {
    pub fn from_process() -> Self {
        // Empty variables count as unset, as they do for the AWS CLI.
        let var = |name| std::env::var(name).ok().filter(|value| !value.is_empty());
        Self {
            aws_profile: var("AWS_PROFILE"),
            aws_config_file: var("AWS_CONFIG_FILE"),
            aws_shared_credentials_file: var("AWS_SHARED_CREDENTIALS_FILE"),
            shell: var("SHELL"),
            home_dir: dirs::home_dir(),
        }
    }

    /// Expand a leading `~` to the home directory, as the AWS SDKs do.
    fn expand_home(&self, path: &str) -> PathBuf {
        let rest = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\"));
        match (rest, &self.home_dir) {
            (Some(rest), Some(home)) => home.join(rest),
            _ => PathBuf::from(path),
        }
    }

    /// `~/.aws/<name>`, the default location of the shared AWS files.
    fn default_aws_file(&self, name: &str) -> Option<PathBuf> {
        self.home_dir
            .as_ref()
            .map(|home| home.join(".aws").join(name))
    }
}

/// AWS SDK settings that override the SDK's own environment-based defaults.
/// Children started by `--shell` inherit them too.
#[derive(Clone, Debug, Default)]
pub struct SdkSettings {
    /// `--profile`; otherwise the SDK reads `AWS_PROFILE`.
    pub profile: Option<String>,
    /// `--credentials-file`; otherwise the SDK reads `AWS_SHARED_CREDENTIALS_FILE`.
    pub credentials_file: Option<PathBuf>,
    /// `--region`; otherwise the SDK's region chain, then `us-east-1`.
    pub region: Option<String>,
}

/// A profile in a credentials file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileTarget {
    pub name: String,
    pub file: PathBuf,
}

/// What to do with the session credentials.
#[derive(Clone, Debug, Default)]
pub struct Outputs {
    /// `--update-profile`: store the session in this profile, or reuse it.
    pub session_profile: Option<ProfileTarget>,
    /// `--export`: print the credentials in this format.
    pub export: Option<ExportFormat>,
    /// `--shell`: start this shell with the credentials.
    pub shell: Option<String>,
}

impl Outputs {
    fn is_empty(&self) -> bool {
        self.session_profile.is_none() && self.export.is_none() && self.shell.is_none()
    }

    /// Whether any output shows the caller's identity in a shell prompt.
    pub fn shows_prompt(&self) -> bool {
        self.shell.is_some() || self.export.is_some_and(ExportFormat::shows_prompt)
    }
}

/// Everything a run needs to know, resolved and validated.
#[derive(Clone, Debug)]
pub struct Config {
    /// The profile holding the long-term credentials: `--profile`,
    /// `AWS_PROFILE`, or `default`.
    pub profile: String,
    /// The shared config file, searched for `mfa_serial`.
    pub config_file: Option<PathBuf>,
    /// The shared credentials file, searched for `mfa_serial`.
    pub credentials_file: Option<PathBuf>,
    pub sdk: SdkSettings,
    /// `--arn`: the MFA device to use instead of looking one up.
    pub mfa_device: Option<String>,
    pub code: Option<MfaCode>,
    pub duration_secs: i32,
    /// `--force`: never reuse the `--update-profile` session.
    pub force: bool,
    pub outputs: Outputs,
}

impl Config {
    pub fn new(args: Args, env: &Env) -> Result<Self, CliError> {
        let cli_credentials_file = args.credentials_file.map(|path| env.expand_home(&path));
        let credentials_file =
            cli_credentials_file
                .clone()
                .or_else(|| match &env.aws_shared_credentials_file {
                    Some(path) => Some(env.expand_home(path)),
                    None => env.default_aws_file("credentials"),
                });
        let config_file = match &env.aws_config_file {
            Some(path) => Some(env.expand_home(path)),
            None => env.default_aws_file("config"),
        };

        let shell = env
            .shell
            .clone()
            .unwrap_or_else(|| DEFAULT_SHELL.to_owned());
        let session_profile = match (args.session_profile, &credentials_file) {
            (Some(name), Some(file)) => Some(ProfileTarget {
                name,
                file: file.clone(),
            }),
            (Some(_), None) => return Err(CliError::NoCredentialsFile),
            (None, _) => None,
        };
        let outputs = Outputs {
            session_profile,
            export: args.export.then(|| {
                args.format
                    .unwrap_or_else(|| ExportFormat::Shell(Shell::detect(&shell)))
            }),
            shell: args.shell.then_some(shell),
        };
        // Clap enforces this for the command line; this guards library callers.
        if outputs.is_empty() {
            return Err(CliError::NoOutputMode);
        }

        Ok(Self {
            profile: args
                .profile
                .clone()
                .or_else(|| env.aws_profile.clone())
                .unwrap_or_else(|| DEFAULT_PROFILE.to_owned()),
            config_file,
            credentials_file,
            sdk: SdkSettings {
                profile: args.profile,
                credentials_file: cli_credentials_file,
                region: args.region,
            },
            mfa_device: args.arn,
            code: args.code,
            duration_secs: args.duration,
            force: args.force,
            outputs,
        })
    }

    pub fn config_file(&self) -> Option<&Path> {
        self.config_file.as_deref()
    }

    pub fn credentials_file(&self) -> Option<&Path> {
        self.credentials_file.as_deref()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use clap::Parser;

    pub fn args(args: &[&str]) -> Args {
        Args::try_parse_from(std::iter::once("aws-mfa-session").chain(args.iter().copied()))
            .unwrap()
    }

    pub fn home_env() -> Env {
        Env {
            home_dir: Some(PathBuf::from("/home/alice")),
            ..Env::default()
        }
    }

    fn config(arguments: &[&str], env: &Env) -> Config {
        Config::new(args(arguments), env).unwrap()
    }

    #[test]
    fn test_profile_resolution() {
        let mut env = home_env();
        assert_eq!(config(&["-e"], &env).profile, "default");

        env.aws_profile = Some("from-env".to_owned());
        let from_env = config(&["-e"], &env);
        assert_eq!(from_env.profile, "from-env");
        assert_eq!(
            from_env.sdk.profile, None,
            "the SDK reads AWS_PROFILE itself"
        );

        let from_cli = config(&["-e", "-p", "from-cli"], &env);
        assert_eq!(from_cli.profile, "from-cli");
        assert_eq!(from_cli.sdk.profile.as_deref(), Some("from-cli"));
    }

    #[test]
    fn test_default_file_locations() {
        let config = config(&["-e"], &home_env());
        assert_eq!(
            config.credentials_file(),
            Some(Path::new("/home/alice/.aws/credentials"))
        );
        assert_eq!(
            config.config_file(),
            Some(Path::new("/home/alice/.aws/config"))
        );
        assert_eq!(config.sdk.credentials_file, None);
    }

    #[test]
    fn test_file_locations_from_env() {
        let env = Env {
            aws_config_file: Some("~/custom/config".to_owned()),
            aws_shared_credentials_file: Some("/etc/aws/credentials".to_owned()),
            ..home_env()
        };
        let config = config(&["-e"], &env);
        assert_eq!(
            config.config_file(),
            Some(Path::new("/home/alice/custom/config"))
        );
        assert_eq!(
            config.credentials_file(),
            Some(Path::new("/etc/aws/credentials"))
        );
        assert_eq!(
            config.sdk.credentials_file, None,
            "the SDK reads the variable itself"
        );
    }

    #[test]
    fn test_credentials_file_from_cli_wins() {
        let env = Env {
            aws_shared_credentials_file: Some("/from/env".to_owned()),
            ..home_env()
        };
        let config = config(&["-u", "session", "-f", "~/.aws/credentials2"], &env);
        let expected = Path::new("/home/alice/.aws/credentials2");
        assert_eq!(config.credentials_file(), Some(expected));
        assert_eq!(config.sdk.credentials_file.as_deref(), Some(expected));
        assert_eq!(
            config.outputs.session_profile,
            Some(ProfileTarget {
                name: "session".to_owned(),
                file: expected.to_owned(),
            })
        );
    }

    #[test]
    fn test_expand_home() {
        let env = home_env();
        assert_eq!(env.expand_home("~/x"), PathBuf::from("/home/alice/x"));
        assert_eq!(env.expand_home("~\\x"), PathBuf::from("/home/alice/x"));
        assert_eq!(env.expand_home("/abs/x"), PathBuf::from("/abs/x"));
        assert_eq!(env.expand_home("rel/~/x"), PathBuf::from("rel/~/x"));
        assert_eq!(env.expand_home("~other/x"), PathBuf::from("~other/x"));
        assert_eq!(Env::default().expand_home("~/x"), PathBuf::from("~/x"));
    }

    #[test]
    fn test_update_profile_needs_a_credentials_file() {
        let result = Config::new(args(&["-u", "session"]), &Env::default());
        assert!(matches!(result, Err(CliError::NoCredentialsFile)));

        // Other outputs work without a home directory.
        let config = Config::new(args(&["-e"]), &Env::default()).unwrap();
        assert_eq!(config.credentials_file(), None);
        assert_eq!(config.config_file(), None);
    }

    #[test]
    fn test_export_format_detected_from_shell() {
        let env = Env {
            shell: Some("/usr/bin/fish".to_owned()),
            ..home_env()
        };
        assert_eq!(
            config(&["-e"], &env).outputs.export,
            Some(ExportFormat::Shell(Shell::Fish))
        );
        assert_eq!(
            config(&["-e", "--format", "json"], &env).outputs.export,
            Some(ExportFormat::Json)
        );
        assert_eq!(config(&["-s"], &env).outputs.export, None);
    }

    #[test]
    fn test_shell_program() {
        let env = Env {
            shell: Some("/usr/bin/zsh".to_owned()),
            ..home_env()
        };
        assert_eq!(
            config(&["-s"], &env).outputs.shell.as_deref(),
            Some("/usr/bin/zsh")
        );
        assert_eq!(
            config(&["-s"], &home_env()).outputs.shell.as_deref(),
            Some(DEFAULT_SHELL)
        );
        assert_eq!(config(&["-e"], &env).outputs.shell, None);
    }

    #[test]
    fn test_shows_prompt() {
        let env = home_env();
        assert!(config(&["-s"], &env).outputs.shows_prompt());
        assert!(
            config(&["-e", "--format", "bash"], &env)
                .outputs
                .shows_prompt()
        );
        assert!(
            !config(&["-e", "--format", "json"], &env)
                .outputs
                .shows_prompt()
        );
        assert!(!config(&["-u", "session"], &env).outputs.shows_prompt());
    }

    #[test]
    fn test_passes_through_session_settings() {
        let config = config(
            &[
                "-e",
                "-c",
                "123456",
                "-a",
                "GAHT1",
                "-d",
                "900",
                "-r",
                "eu-west-1",
            ],
            &home_env(),
        );
        assert_eq!(config.code.unwrap().as_str(), "123456");
        assert_eq!(config.mfa_device.as_deref(), Some("GAHT1"));
        assert_eq!(config.duration_secs, 900);
        assert_eq!(config.sdk.region.as_deref(), Some("eu-west-1"));
        assert!(!config.force);
    }

    #[test]
    fn test_rejects_args_without_output_mode() {
        // Library callers can build `Args` without clap's validation.
        let mut no_output = args(&["-e"]);
        no_output.export = false;
        let result = Config::new(no_output, &home_env());
        assert!(matches!(result, Err(CliError::NoOutputMode)));
    }
}
