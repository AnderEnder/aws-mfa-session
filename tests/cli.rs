//! End-to-end tests of the binary. None of them reach AWS: they cover argument
//! handling, the offline reuse of a saved session, and failing fast when AWS
//! is unreachable.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const SAVED_SESSION: &str = "\
[default]
aws_access_key_id = AKIALONGTERM
aws_secret_access_key = LONGTERMSECRET

[session]
aws_access_key_id = ASIASAVED
aws_secret_access_key = SAVEDSECRET
aws_session_token = SAVEDTOKEN
expiration = 2099-01-01T00:00:00Z
";

/// A scratch home directory, and the binary isolated from the caller's AWS setup.
struct Sandbox {
    dir: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn credentials_file(&self) -> PathBuf {
        self.dir.path().join("credentials")
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_aws-mfa-session"));
        for var in [
            "AWS_PROFILE",
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_SHARED_CREDENTIALS_FILE",
            "AWS_REGION",
            "AWS_DEFAULT_REGION",
            "AWS_ENDPOINT_URL",
            "RUST_LOG",
        ] {
            command.env_remove(var);
        }
        command
            .env("HOME", self.dir.path())
            .env("AWS_CONFIG_FILE", self.dir.path().join("config"))
            .env("SHELL", "/bin/bash")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null());
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn path_arg(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn help_lists_options() {
    let output = Sandbox::new().run(&["--help"]);
    assert!(output.status.success());
    let help = stdout(&output);
    for option in [
        "--export",
        "--shell",
        "--update-profile",
        "--format <FORMAT>",
        "--force",
    ] {
        assert!(help.contains(option), "help is missing {option}:\n{help}");
    }
    assert!(
        help.contains("powershell"),
        "format values are listed:\n{help}"
    );
}

#[test]
fn version() {
    let output = Sandbox::new().run(&["--version"]);
    assert!(output.status.success());
    assert_eq!(
        stdout(&output).trim(),
        format!("aws-mfa-session {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn requires_an_output_mode() {
    let output = Sandbox::new().run(&["--code", "123456"]);
    assert_eq!(output.status.code(), Some(2));
    let message = stderr(&output);
    assert!(message.contains("--shell"), "{message}");
    assert!(message.contains("--export"), "{message}");
    assert!(message.contains("--update-profile"), "{message}");
}

#[test]
fn rejects_an_invalid_code() {
    let output = Sandbox::new().run(&["-e", "--code", "12345"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("MFA code must be exactly 6 digits"));
}

#[test]
fn format_requires_export() {
    let output = Sandbox::new().run(&["-s", "--format", "json"]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn reuses_valid_profile_offline() {
    let sandbox = Sandbox::new();
    let credentials = sandbox.credentials_file();
    fs::write(&credentials, SAVED_SESSION).unwrap();

    let output = sandbox.run(&["-f", path_arg(&credentials), "-u", "session"]);

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).is_empty());
    let message = stderr(&output);
    assert!(message.contains("Reusing profile 'session'"), "{message}");
    assert!(message.contains("--force"), "{message}");
    assert_eq!(fs::read_to_string(&credentials).unwrap(), SAVED_SESSION);
}

#[test]
fn exports_reused_profile_as_json() {
    let sandbox = Sandbox::new();
    let credentials = sandbox.credentials_file();
    fs::write(&credentials, SAVED_SESSION).unwrap();

    let output = sandbox.run(&[
        "-f",
        path_arg(&credentials),
        "-u",
        "session",
        "-e",
        "--format",
        "json",
    ]);

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        r#"{
  "Version": 1,
  "AccessKeyId": "ASIASAVED",
  "SecretAccessKey": "SAVEDSECRET",
  "SessionToken": "SAVEDTOKEN",
  "Expiration": "2099-01-01T00:00:00Z"
}
"#
    );
}

#[test]
fn fails_before_prompting_when_aws_is_unreachable() {
    let sandbox = Sandbox::new();
    let output = sandbox
        .command()
        .args(["-f", path_arg(&sandbox.credentials_file()), "-u", "session"])
        .env("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE")
        .env("AWS_SECRET_ACCESS_KEY", "secret")
        .env("AWS_REGION", "us-east-1")
        .env("AWS_ENDPOINT_URL", "http://127.0.0.1:1")
        .env("AWS_MAX_ATTEMPTS", "1")
        .env("AWS_EC2_METADATA_DISABLED", "true")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let message = stderr(&output);
    assert!(message.contains("GetCallerIdentity failed"), "{message}");
    assert!(
        !message.contains("MFA code"),
        "must fail before asking for a code: {message}"
    );
    assert!(!sandbox.credentials_file().exists());
}
