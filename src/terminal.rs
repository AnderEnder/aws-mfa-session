//! The user-facing side effects of a run, behind a trait so the session flow
//! can be tested without a TTY or spawning processes.

use std::io::{self, Write};
use std::process::{Command, Stdio};

use dialoguer::Input;

use crate::error::CliError;
use crate::mfa::MfaCode;
use crate::shell::ShellLaunch;

pub(crate) trait Terminal {
    /// Ask the user for the current code from their MFA device.
    fn read_mfa_code(&mut self) -> Result<MfaCode, CliError>;

    /// Run the user's command that prints an MFA code, and return its output.
    fn run_mfa_process(&mut self, command: &str) -> Result<String, CliError>;

    /// Print command output, such as exported credentials, to stdout.
    fn print(&mut self, text: &str) -> Result<(), CliError>;

    /// Tell the user what happened, on stderr so it never mixes with output.
    fn note(&mut self, message: &str);

    /// Run an interactive shell and wait for it to exit.
    fn run_shell(&mut self, launch: &ShellLaunch) -> Result<(), CliError>;
}

/// The real terminal and process environment.
pub(crate) struct SystemTerminal;

impl Terminal for SystemTerminal {
    fn read_mfa_code(&mut self) -> Result<MfaCode, CliError> {
        // Prompts on stderr, so it works inside `eval "$(aws-mfa-session -e)"`,
        // and asks again until the input is a valid code.
        Input::new()
            .with_prompt("Enter MFA code")
            .interact_text()
            .map_err(CliError::Prompt)
    }

    fn run_mfa_process(&mut self, command: &str) -> Result<String, CliError> {
        tracing::debug!("running the MFA code command");
        // Only stdout is captured, so the command can still prompt the user,
        // e.g. to touch a YubiKey.
        let output = shell_command(command)
            .stdin(Stdio::inherit())
            .stderr(Stdio::inherit())
            .output()
            .map_err(CliError::MfaProcess)?;
        if !output.status.success() {
            let status = io::Error::other(output.status.to_string());
            return Err(CliError::MfaProcess(status));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn print(&mut self, text: &str) -> Result<(), CliError> {
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(text.as_bytes())
            .and_then(|()| stdout.flush())
            .map_err(CliError::Stdout)
    }

    fn note(&mut self, message: &str) {
        // Best effort: a closed stderr must not fail the run.
        let _ = writeln!(io::stderr(), "{message}");
    }

    fn run_shell(&mut self, launch: &ShellLaunch) -> Result<(), CliError> {
        Command::new(&launch.program)
            .envs(launch.env.iter().map(|(name, value)| (name, value)))
            .status()
            .map(drop)
            .map_err(|source| CliError::Shell {
                program: launch.program.clone(),
                source,
            })
    }
}

/// `command` run by the platform's shell, the way aws-vault runs `mfa_process`.
#[cfg(not(windows))]
fn shell_command(command: &str) -> Command {
    let mut shell = Command::new("/bin/sh");
    shell.arg("-c").arg(command);
    shell
}

#[cfg(windows)]
fn shell_command(command: &str) -> Command {
    use std::os::windows::process::CommandExt;
    let mut shell = Command::new("cmd.exe");
    // `/S` strips exactly the outer quotes added here and runs the rest as
    // written, quoted program paths included. `/D` skips AutoRun commands,
    // whose output would be taken for the code.
    shell.raw_arg(format!("/D /S /C \"{command}\""));
    shell
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_mfa_process_output() {
        let output = SystemTerminal.run_mfa_process("echo 123456").unwrap();
        assert_eq!(output.trim(), "123456");
    }

    #[test]
    fn test_mfa_process_failure() {
        let error = SystemTerminal.run_mfa_process("exit 3").unwrap_err();
        assert!(matches!(error, CliError::MfaProcess(_)), "{error:?}");
        let status = error.source().unwrap().to_string();
        assert!(status.ends_with('3'), "{status}");
    }

    #[cfg(unix)]
    #[test]
    fn test_mfa_process_runs_through_sh() {
        let output = SystemTerminal
            .run_mfa_process("printf '12%s' 3456 | cat")
            .unwrap();
        assert_eq!(output, "123456");
    }

    #[cfg(windows)]
    #[test]
    fn test_mfa_process_runs_through_cmd() {
        // A quoted program path, which plain `cmd /C` can mangle.
        let output = SystemTerminal
            .run_mfa_process(r#""%SystemRoot%\System32\cmd.exe" /c echo 123456"#)
            .unwrap();
        assert_eq!(output.trim(), "123456");
    }
}
