//! The user-facing side effects of a run, behind a trait so the session flow
//! can be tested without a TTY or spawning processes.

use std::io::{self, Write};
use std::process::Command;

use dialoguer::Input;

use crate::error::CliError;
use crate::mfa::MfaCode;
use crate::shell::ShellLaunch;

pub(crate) trait Terminal {
    /// Ask the user for the current code from their MFA device.
    fn read_mfa_code(&mut self) -> Result<MfaCode, CliError>;

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
